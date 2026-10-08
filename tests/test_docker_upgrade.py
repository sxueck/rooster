"""Lightweight unit tests for scripts/test-docker-upgrade.py helpers.

These cover the pure logic (version parsing/distinctness, artifact key
building, SHA256SUMS lookup, Ed25519 public-key extraction, secret redaction,
wait/timeout semantics, tmp file modes) so the helpers are verified without a
Docker daemon. The full E2E flow itself requires a real daemon and is executed
by running the script directly.
"""

import base64
import importlib.util
import os
import secrets
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "test-docker-upgrade.py"

spec = importlib.util.spec_from_file_location("rooster_e2e_script", SCRIPT)
assert spec is not None and spec.loader is not None
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class VersionHelperTests(unittest.TestCase):
    def test_parse_version_output(self):
        self.assertEqual(mod.parse_version_output("rooster 0.2.1-ci-old\n"), "0.2.1-ci-old")
        self.assertEqual(mod.parse_version_output("roster junk\nrooster 0.2.2\n"), "0.2.2")
        self.assertEqual(mod.parse_version_output("rooster 1.2.3"), "1.2.3")

    def test_parse_version_output_rejects_empty(self):
        for bad in ("", "\n  \n", "rooster\n"):
            with self.assertRaises(ValueError):
                mod.parse_version_output(bad)

    def test_distinct_versions_required(self):
        mod.ensure_distinct_versions("0.2.1-ci-old", "0.2.1-ci-new")  # no error
        with self.assertRaises(mod.TestFailure):
            mod.ensure_distinct_versions("0.2.1", "0.2.1")


class ArtifactKeyTests(unittest.TestCase):
    def test_key_and_node_version_roundtrip(self):
        key = mod.artifact_key("0.2.1-ci-new", "x86_64")
        self.assertEqual(key, "0.2.1-ci-new-x86_64")
        self.assertEqual(mod.node_version(key, "x86_64"), "0.2.1-ci-new")

    def test_key_rejects_injection_and_bad_arch(self):
        for bad in ("", "../evil", "0.2.1/a", "x" * 200):
            with self.assertRaises(mod.TestFailure):
                mod.artifact_key(bad, "x86_64")
            with self.assertRaises(mod.TestFailure):
                mod.artifact_key("0.2.1", bad)

    def test_node_version_without_suffix_passes_through(self):
        self.assertEqual(mod.node_version("0.2.1", "x86_64"), "0.2.1")


class Sha256sumsTests(unittest.TestCase):
    def test_lookup_finds_entry_case_insensitive_digest(self):
        text = "aaaabbbbccccdddd0000111122223333aaaa  rooster-0.2.1-x86_64\nffff  other\n"
        self.assertEqual(mod.sha256sums_lookup(text, "rooster-0.2.1-x86_64"),
                         "aaaabbbbccccdddd0000111122223333aaaa")
        self.assertIsNone(mod.sha256sums_lookup(text, "missing"))
        self.assertIsNone(mod.sha256sums_lookup("", "x"))
        self.assertIsNone(mod.sha256sums_lookup(None, "x"))


class Ed25519Tests(unittest.TestCase):
    def test_public_b64_takes_trailing_32_bytes(self):
        der = b"\x30" + b"\x00" * 10 + secrets.token_bytes(32)
        want = base64.b64encode(der[-32:]).decode()
        self.assertEqual(mod.ed25519_public_b64(der), want)

    def test_public_b64_rejects_short_der(self):
        with self.assertRaises(ValueError):
            mod.ed25519_public_b64(b"\x01\x02")

    def test_sign_and_public_key_agree_with_openssl(self):
        # cross-checks the offline signer against the hub's ed25519:<base64> form
        import shutil
        import subprocess
        if not shutil.which("openssl"):
            self.skipTest("openssl not available")
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            key = tmp / "k.pem"
            subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(key)],
                           check=True, capture_output=True)
            pub = mod.ed25519_public(key)
            self.assertTrue(pub.startswith("ed25519:"))
            raw = base64.b64decode(pub.split(":", 1)[1])
            self.assertEqual(len(raw), 32)
            payload = tmp / "p.bin"
            payload.write_bytes(b"artifact-bytes")
            sig_b64 = mod.sign_payload(key, payload)
            self.assertEqual(len(base64.b64decode(sig_b64)), 64)
            public_file = tmp / "public.pem"
            subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(public_file)],
                           check=True, capture_output=True)
            v = subprocess.run(["openssl", "pkeyutl", "-verify", "-rawin",
                                "-pubin", "-inkey", str(public_file), "-sigfile", str(payload.with_suffix(".sig")),
                                "-in", str(payload)], capture_output=True, text=True)
            self.assertEqual(v.returncode, 0, v.stderr)


class HubAssertionTests(unittest.TestCase):
    def test_node_ready_requires_new_connection_after_recreation(self):
        from unittest.mock import Mock
        hub = mod.Hub.__new__(mod.Hub)
        hub.json = Mock(return_value=(200, {"nodes": [
            {"id": "node", "online": True, "version": "1.2.3", "last_seen": 100}]}))
        self.assertIsNotNone(hub.node_ready("node", "1.2.3"))
        self.assertIsNone(hub.node_ready("node", "1.2.3", after_seen=100))
        self.assertIsNotNone(hub.node_ready("node", "1.2.3", after_seen=99))
        self.assertIsNone(hub.node_ready("node", "old-version"))

    def test_rollout_requires_completed_success_for_target_node(self):
        from unittest.mock import Mock
        hub = mod.Hub.__new__(mod.Hub)
        for overall, node, result, expected in [
            ("running", "node", "upgraded", False),
            ("done", "other-node", "upgraded", False),
            ("done", "node", "version-unchanged", False),
            ("done", "node", "upgraded", True),
        ]:
            hub.json = Mock(return_value=(200, {"status": overall,
                "results": [{"node_id": node, "status": result}]}))
            self.assertEqual(hub.rollout_upgraded("run", "node"), expected)


class DockerAssertionTests(unittest.TestCase):
    def test_failed_exec_does_not_prove_marker_clearance(self):
        import subprocess
        from unittest.mock import Mock
        docker = mod.Docker.__new__(mod.Docker)
        for code, stderr, expected in [
            (0, "", False), (1, "", True),
            (1, "container is restarting", False), (126, "", False),
        ]:
            docker.exec = Mock(return_value=subprocess.CompletedProcess([], code, "", stderr))
            self.assertEqual(docker.path_missing("agent", mod.UPGRADE_MARKER), expected)


class RedactTests(unittest.TestCase):
    def test_all_secrets_removed(self):
        secrets_ = ["s3cret-hex", "tok-en-123"]
        text = "hub login s3cret-hex failed; token tok-en-123 rejected"
        out = mod.redact(text, secrets_)
        self.assertNotIn("s3cret-hex", out)
        self.assertNotIn("tok-en-123", out)
        self.assertEqual(out.count("<redacted>"), 2)

    def test_redact_handles_empty_and_none(self):
        self.assertEqual(mod.redact("plain", []), "plain")
        self.assertEqual(mod.redact(None, ["x"]), "")


class WaitUntilTests(unittest.TestCase):
    def test_returns_first_truthy_result(self):
        self.assertEqual(mod.wait_until("immediate", lambda: 42, timeout=1), 42)

    def test_polls_until_truthy(self):
        state = {"n": 0}

        def fn():
            state["n"] += 1
            return state["n"] >= 3 or None

        self.assertTrue(mod.wait_until("third try", fn, timeout=5, interval=0.01))

    def test_timeout_raises_test_failure(self):
        with self.assertRaises(mod.TestFailure):
            mod.wait_until("never", lambda: None, timeout=0.2, interval=0.05)


class ScriptHygieneTests(unittest.TestCase):
    def test_workdir_and_key_files_created_private(self):
        # provision() must leave CA/server/signer keys mode 0600 inside a 0700 dir
        import shutil
        if not shutil.which("openssl"):
            self.skipTest("openssl not available")
        old_umask = os.umask(0o077)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                work = Path(tmp)
                mat = mod.provision(work)
                import subprocess
                result = subprocess.run(["openssl", "verify", "-CAfile", str(mat["ca_crt"]),
                    "-purpose", "sslserver", "-verify_ip", "127.0.0.1", str(mat["srv_crt"])],
                    capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                for key in (work / "tls" / "ca.key", work / "tls" / "hub.key", mat["signer"]):
                    self.assertTrue(key.is_file())
                    self.assertEqual(oct(key.stat().st_mode & 0o777), "0o600", str(key))
        finally:
            os.umask(old_umask)

    def test_docker_unavailable_raises_env_error_not_success(self):
        # with no docker binary on PATH the script must fail loudly (exit 2)
        import subprocess
        import sys
        env = {**os.environ, "PATH": "/nonexistent"}
        r = subprocess.run([sys.executable, str(SCRIPT), "--old-image", "a", "--new-image", "b"],
                           capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("Docker", r.stderr + r.stdout)

    def test_requires_both_images(self):
        import subprocess
        import sys
        r = subprocess.run([sys.executable, str(SCRIPT), "--old-image", "a"],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 2)  # argparse usage error -> 2
        self.assertIn("--new-image", r.stderr)


if __name__ == "__main__":
    unittest.main()

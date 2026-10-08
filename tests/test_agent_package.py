import base64
import gzip
import hashlib
import importlib.util
import json
import lzma
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("publish_agent", ROOT / "scripts/publish-agent.py")
assert spec is not None and spec.loader is not None
publish = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publish)


class AgentPackageTests(unittest.TestCase):
    def test_raw_compressed_manifest_and_checksums_agree(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            binary = tmp / "rooster"
            binary.write_text('#!/bin/sh\ncase "$1" in --version) echo "rooster 1.2.3";; agent) exit 0;; *) exit 1;; esac\n')
            binary.chmod(0o755)
            out = tmp / "dist"
            subprocess.run(["sh", str(ROOT / "scripts/package-agent.sh"), str(binary), str(out), "x86_64"], check=True)
            name = "rooster-1.2.3-x86_64"
            raw = (out / name).read_bytes()
            self.assertEqual(raw, binary.read_bytes())
            self.assertEqual(gzip.decompress((out / (name + ".gz")).read_bytes()), raw)
            self.assertEqual(lzma.decompress((out / (name + ".xz")).read_bytes()), raw)
            self.assertEqual(json.loads((out / "manifest.json").read_text()),
                {"version": "1.2.3", "arch": "x86_64", "binary": name})
            for line in (out / "SHA256SUMS").read_text().splitlines():
                digest, filename = line.split()
                self.assertEqual(digest, hashlib.sha256((out / filename).read_bytes()).hexdigest())
            self.assertEqual((out / "SHA256SUMS").read_bytes(), (out / "SHA256SUMS-x86_64").read_bytes())

    def test_signature_verifies_raw_bytes_and_rejects_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            key, public, artifact, signature = (tmp / f for f in ("key.pem", "pub.pem", "rooster-1.2.3-x86_64", "sig"))
            subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(key)], check=True, capture_output=True)
            artifact.write_bytes(b"raw-agent-binary")
            raw, encoded = publish.sign(artifact, key)
            self.assertEqual(len(base64.b64decode(encoded.split(":", 1)[1])), 32)
            signature.write_bytes(raw)
            subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(public)], check=True, capture_output=True)
            args = ["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(public), "-in", str(artifact), "-sigfile", str(signature)]
            self.assertEqual(subprocess.run(args, capture_output=True).returncode, 0)
            artifact.write_bytes(b"tampered-agent-binary")
            self.assertNotEqual(subprocess.run(args, capture_output=True).returncode, 0)

    def test_upload_refuses_redirects_before_forwarding_token(self):
        with self.assertRaisesRegex(ValueError, "redirects are refused"):
            publish.NoRedirect().redirect_request(None, None, 307, "redirect", {}, "https://other.test")

    def test_refuses_unsigned_or_unverified_upload_mode(self):
        result = subprocess.run(["python3", str(ROOT / "scripts/publish-agent.py"), "rooster-1.2.3-x86_64",
            "--key", "unused", "--hub", "http://example.test", "--token-file", "unused"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("TLS verification cannot be disabled", result.stderr)


if __name__ == "__main__":
    unittest.main()

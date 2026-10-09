import base64
import contextlib
import gzip
import hashlib
import http.server
import importlib.util
import json
import lzma
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("publish_agent", ROOT / "scripts/publish-agent.py")
assert spec is not None and spec.loader is not None
publish = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publish)


def hub_cert(workdir):
    """Self-signed certificate that is also its own CA, trusted via --cacert (SAN 127.0.0.1)."""
    key, crt = workdir / "hub.key", workdir / "hub.crt"
    key.touch(mode=0o600)
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
        "-nodes", "-subj", "/CN=127.0.0.1", "-days", "2", "-keyout", str(key), "-out", str(crt),
        "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,digitalSignature,keyCertSign",
        "-addext", "extendedKeyUsage=serverAuth"],
        check=True, capture_output=True, env={**os.environ, "OPENSSL_CONF": os.devnull})
    return crt, key


@contextlib.contextmanager
def hub(crt, key, respond):
    """Serve HTTPS on 127.0.0.1, recording (method, path, authorization, body) per request.

    Yields (port, hits); respond(path) returns (status, extra_headers).
    """
    hits = []

    class Handler(http.server.BaseHTTPRequestHandler):
        # HTTP/1.1 plus Content-Length so curl sees a complete response before the
        # server drops the TLS session; a bare HTTP/1.0 close trips curl (56).
        protocol_version = "HTTP/1.1"

        def record(self):
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            hits.append((self.command, self.path, self.headers.get("Authorization"), body))
            status, extra = respond(self.path)
            self.send_response(status)
            for name, value in extra.items():
                self.send_header(name, value)
            self.send_header("Content-Length", "0")
            self.end_headers()

        do_POST = do_GET = record

        def handle(self):
            try:
                super().handle()
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, format, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(crt), str(key))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port, hits
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


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

    def test_refuses_unsigned_or_unverified_upload_mode(self):
        result = subprocess.run(["python3", str(ROOT / "scripts/publish-agent.py"), "rooster-1.2.3-x86_64",
            "--key", "unused", "--hub", "http://example.test", "--token-file", "unused"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("TLS verification cannot be disabled", result.stderr)


class HubUploadTests(unittest.TestCase):
    """publish-agent.py uploads with curl, which only keeps the session token on the
    trusted origin as long as nothing makes it follow a redirect."""

    TOKEN = "hub-session-token"

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.artifact = self.tmp / "rooster-9.9.9-x86_64"
        self.artifact.write_bytes(b"raw-agent-binary")
        self.signer = self.tmp / "signer.key"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(self.signer)],
            check=True, capture_output=True)
        self.token_file = self.tmp / "token"
        self.token_file.write_text(self.TOKEN + "\n")
        os.chmod(self.token_file, 0o600)
        self.crt, self.key = hub_cert(self.tmp)
        self.addCleanup(self._tmp.cleanup)

    def publish(self, hub_url, ca):
        return subprocess.run([sys.executable, str(ROOT / "scripts/publish-agent.py"),
            str(self.artifact), "--key", str(self.signer), "--hub", hub_url,
            "--token-file", str(self.token_file), "--ca-file", str(ca)],
            capture_output=True, text=True, timeout=120)

    def test_upload_posts_the_raw_artifact_to_the_trusted_origin(self):
        with hub(self.crt, self.key, lambda path: (200, {})) as (port, hits):
            result = self.publish(f"https://127.0.0.1:{port}", self.crt)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Uploaded", result.stdout)
        self.assertEqual([(m, p, a) for m, p, a, _ in hits],
            [("POST", "/v0/upgrades", "Bearer " + self.TOKEN)])
        self.assertEqual(hits[0][3], self.artifact.read_bytes())

    def test_upload_refuses_redirects_before_forwarding_token(self):
        with contextlib.ExitStack() as stack:
            decoy_port, decoy_hits = stack.enter_context(hub(self.crt, self.key, lambda path: (200, {})))
            hub_port, hits = stack.enter_context(hub(self.crt, self.key,
                lambda path: (307, {"Location": f"https://127.0.0.1:{decoy_port}/v0/upgrades"})))
            result = self.publish(f"https://127.0.0.1:{hub_port}", self.crt)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("upload failed: HTTP 307", result.stderr)
        self.assertEqual(len(hits), 1)
        self.assertEqual(decoy_hits, [])


if __name__ == "__main__":
    unittest.main()

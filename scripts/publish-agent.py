#!/usr/bin/env python3
"""Sign a raw agent artifact offline; optionally upload it to a trusted Hub."""
import argparse
import base64
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path


def openssl(*args):
    return subprocess.run(["openssl", *map(str, args)], check=True, capture_output=True).stdout


def sign(artifact, key):
    with tempfile.TemporaryDirectory(prefix="rooster-sign-") as tmp:
        sig = Path(tmp) / "signature"
        openssl("pkeyutl", "-sign", "-rawin", "-inkey", key, "-in", artifact, "-out", sig)
        raw = sig.read_bytes()
        if len(raw) != 64:
            raise ValueError("expected a 64-byte Ed25519 signature")
        public = openssl("pkey", "-in", key, "-pubout", "-outform", "DER")
        if not public.startswith(bytes.fromhex("302a300506032b6570032100")) or len(public) != 44:
            raise ValueError("signing key must be Ed25519")
        return raw, "ed25519:" + base64.b64encode(public[-32:]).decode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path, help="raw rooster-VERSION-ARCH from the image or release")
    parser.add_argument("--key", required=True, type=Path, help="offline Ed25519 private key; never copied to the image")
    parser.add_argument("--hub", help="trusted HTTPS Hub origin; omit to sign offline only")
    parser.add_argument("--token-file", type=Path, help="0600 file containing an existing Hub session token")
    parser.add_argument("--ca-file", type=Path, help="trusted server CA for private/self-signed TLS")
    args = parser.parse_args()
    os.umask(0o077)
    name = args.artifact.name
    if not name.startswith("rooster-") or not all(c.isascii() and (c.isalnum() or c in "._-") for c in name):
        parser.error("expected raw artifact name rooster-VERSION-ARCH")
    if name.endswith((".gz", ".xz", ".sig")):
        parser.error("decompress the artifact before signing; signatures cover raw executable bytes")
    if args.hub and (not args.hub.startswith("https://") or not args.token_file):
        parser.error("upload requires --hub https://... and --token-file; TLS verification cannot be disabled")
    raw, public = sign(args.artifact, args.key)
    args.artifact.with_name(name + ".sig").write_bytes(raw)
    meta = {"artifact": name, "sha256": hashlib.sha256(args.artifact.read_bytes()).hexdigest(),
            "signature": base64.b64encode(raw).decode(), "upgrade-public-key": public}
    args.artifact.with_name(name + ".json").write_text(json.dumps(meta, indent=2) + "\n")
    print(f"Signed {name}; set Hub/agent upgrade-public-key to {public}")
    if args.hub:
        token = args.token_file.read_text().strip()
        if not token or args.token_file.stat().st_mode & 0o077:
            parser.error("session token file must be nonempty and accessible only to its owner (chmod 600)")
        # The parser above already rejected non-https origins (no file:/custom schemes).
        upload_url = args.hub.rstrip("/") + "/v0/upgrades"
        if not upload_url.startswith("https://"):
            raise RuntimeError("upload origin must be https")
        # curl over urllib: without -L it never follows redirects, so the session
        # token cannot reach a redirected origin; it also sidesteps Python 3.13+
        # strict TLS rejecting deploy.sh CAs that lack the keyUsage extension.
        cmd = ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "120",
               *( ["--cacert", str(args.ca_file)] if args.ca_file else [] ),
               "-H", "Authorization: Bearer " + token,
               "-H", "X-Rooster-Version: " + name.removeprefix("rooster-"),
               "-H", "X-Rooster-Signature: " + meta["signature"],
               "-H", "Content-Type: application/octet-stream",
               "--data-binary", "@" + str(args.artifact),
               "-X", "POST", upload_url]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0 or not proc.stdout.strip().startswith("2"):
            raise RuntimeError(f"upload failed: HTTP {proc.stdout.strip() or 'n/a'} ({proc.stderr.strip()})")
        print(f"Uploaded {name}; trigger a targeted or staged rollout in the panel")


if __name__ == "__main__":
    main()

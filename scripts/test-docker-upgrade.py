#!/usr/bin/env python3
"""Real Docker signed-upgrade end-to-end validation for rooster.

Requires a *real* Docker daemon on a Linux host (host networking). The script
never builds images: it takes prebuilt --old-image / --new-image (same code,
different compile-time ROOSTER_VERSION, e.g. 0.2.1-ci-old / 0.2.1-ci-new),
starts a real hub container (TLS static, generated CA with SAN 127.0.0.1) and
a real agent container from --old-image, enrolls it via an API register token
(the agent self-registers with token+CSR through hubclient), then exercises:

  1. signed POST /v0/upgrades (x-rooster-version with -<arch> suffix,
     x-rooster-signature Ed25519) + /v0/upgrades/{ver}/rollout (node_id,
     batch_size, wait_secs) and asserts the node reports the new version;
  2. on-disk state: binary digest == uploaded artifact, rooster.prev == old
     image binary, upgrade-pending marker removed, identity cert unchanged;
  3. bad-signature upload rejected (422), binary unchanged;
  4. correctly-signed corrupt payload -> agent applies it, crash-loops, the
     real entrypoint guard rolls back after its 90s grace -> recovered new
     version/digest;
  5. container recreated keeping the named agent data volume -> still new.

Secrets never appear in subprocess argv or stdout: they travel in file bodies
and HTTP bodies only (openssl key *path* args are fine). All created resources
carry a unique UUID suffix and are removed on exit. If Docker is unavailable
the script fails loudly (exit 2) — it never reports a skip as success.

Exit codes: 0 = PASS, 1 = test failure, 2 = environment (docker) problem.
"""

import argparse
import base64
import hashlib
import json
import os
import secrets as pysecrets
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
import socket
from pathlib import Path
from typing import Any, Callable

HUB_PORT = 9443
IMMUTABLE_BIN = "/usr/local/bin/rooster"
MUTABLE_BIN = "/var/lib/rooster/bin/rooster"
AGENT_DATA = "/var/lib/rooster"
UPGRADE_MARKER = f"{AGENT_DATA}/upgrade-pending.json"
AGENT_CERT = f"{AGENT_DATA}/pki/agent.crt"
AGENTS_DIR = "/usr/share/rooster/agents"

COMPONENT_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")


class EnvError(RuntimeError):
    """Docker/tooling unavailable: exit 2."""


class TestFailure(AssertionError):
    """Assertion failed: exit 1."""


def log(msg):
    print(f"[e2e] {msg}", flush=True)


def check(cond, msg):
    if not cond:
        raise TestFailure(msg)


# ---------------------------------------------------------------------------
# Pure helpers (unit-tested in tests/test_docker_upgrade.py)


def parse_version_output(text):
    """`rooster --version` prints `rooster <version>`; return the version."""
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    if not lines:
        raise ValueError("empty --version output")
    parts = lines[-1].split()
    if len(parts) < 2 or not parts[-1]:
        raise ValueError(f"no version token in {lines[-1]!r}")
    return parts[-1]


def valid_component(value):
    return bool(value) and len(value) <= 128 and all(c in COMPONENT_CHARS for c in value)


def ensure_distinct_versions(old, new):
    if old == new:
        raise TestFailure(
            f"images must report distinct actual versions, both report {old!r}; "
            "rebuild with different ROOSTER_VERSION build args"
        )


def artifact_key(version, arch):
    """Hub store key: version plus architecture suffix (x-rooster-version)."""
    for name, part in (("version", version), ("arch", arch)):
        if not valid_component(part):
            raise TestFailure(f"invalid {name} for artifact key: {part!r}")
    return f"{version}-{arch}"


def node_version(key, arch):
    """Mirror hub's artifact_semver(): nodes report the version without -<arch>."""
    suffix = f"-{arch}"
    return key[: -len(suffix)] if key.endswith(suffix) else key


def sha256sums_lookup(text, name):
    """Return the digest listed for `name` in a SHA256SUMS file, else None."""
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1] == name:
            return parts[0].lower()
    return None


def ed25519_public_b64(spki_der):
    """Raw 32-byte Ed25519 public key from a SubjectPublicKeyInfo DER blob."""
    if len(spki_der) < 32:
        raise ValueError("DER too short for an Ed25519 public key")
    return base64.b64encode(spki_der[-32:]).decode()


def redact(text, secrets_):
    out = text or ""
    for s in secrets_:
        if s:
            out = out.replace(s, "<redacted>")
    return out


def wait_until(desc, fn: Callable[[], Any], timeout, interval=3.0) -> Any:
    """Poll fn() until it returns truthy; raise TestFailure on timeout."""
    deadline = time.monotonic() + timeout
    result = fn()
    while not result:
        if time.monotonic() >= deadline:
            raise TestFailure(f"timed out after {int(timeout)}s waiting for: {desc}")
        time.sleep(interval)
        result = fn()
    return result


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Subprocess / docker helpers (list argv only; no shell, no env dumps)


def sh(args, *, timeout=180, check=True, quiet=False, env=None):
    if not quiet:
        log(f"$ {' '.join(args)}")
    run_env = {**os.environ, **(env or {})} if env else None
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=run_env)
    except FileNotFoundError:
        raise EnvError(f"required tool not installed: {args[0]}")
    except subprocess.TimeoutExpired:
        raise EnvError(f"command timed out after {timeout}s: {' '.join(args)}")
    if check and r.returncode != 0:
        raise EnvError(
            f"command failed ({r.returncode}): {' '.join(args)}\n{(r.stderr or r.stdout).strip()[:2000]}"
        )
    return r


class Docker:
    def __init__(self):
        try:
            r = sh(["docker", "version", "--format", "{{.Server.Version}}|{{.Server.Os}}|{{.Server.Arch}}"],
                   timeout=30, quiet=True)
        except EnvError as e:
            raise EnvError(
                "Docker daemon is unavailable — this is a REAL end-to-end test and "
                "refuses to fake success without one.\n"
                f"detail: {e}"
            )
        parts = r.stdout.strip().split("|")
        if len(parts) != 3 or not parts[0]:
            raise EnvError(f"cannot probe docker server: {r.stdout!r} {r.stderr!r}")
        self.server_version, self.server_os, self.server_arch = parts
        if self.server_os != "linux":
            raise EnvError(
                f"docker server OS is {self.server_os!r}; the upgrade flow relies on "
                "--network host containers, which requires a Linux daemon"
            )
        log(f"docker server {self.server_version} (os={self.server_os} arch={self.server_arch})")

    def has_image(self, image):
        return sh(["docker", "image", "inspect", image], timeout=60, quiet=True).returncode == 0

    def image_version(self, image):
        r = sh(["docker", "run", "--rm", "--network", "none", "--entrypoint", IMMUTABLE_BIN, image, "--version"],
               timeout=120)
        return parse_version_output(r.stdout)

    def extract_artifact(self, image, version, arch, outdir, tag):
        """Pull the upgrade artifact out of the image.

        Requires the embedded package dir and verifies it against the image binary.
        Missing packages fail the test instead of silently testing only the raw binary.
        Returns (path, digest, source).
        """
        cname = f"rooster-e2e-extract-{tag}-{uuid.uuid4().hex[:8]}"
        sh(["docker", "create", "--name", cname, image], timeout=60)
        try:
            raw = outdir / f"{tag}-rooster"
            sh(["docker", "cp", f"{cname}:{IMMUTABLE_BIN}", str(raw)], timeout=120)
            raw.chmod(0o700)
            agents = outdir / f"{tag}-agents"
            cp = subprocess.run(["docker", "cp", f"{cname}:{AGENTS_DIR}", str(agents)],
                                capture_output=True, text=True)
            if cp.returncode == 0 and (agents / "manifest.json").is_file():
                manifest = json.loads((agents / "manifest.json").read_text())
                pkg_name = f"rooster-{version}-{arch}"
                pkg = agents / pkg_name
                check(manifest == {"version": version, "arch": arch, "binary": pkg_name},
                      f"embedded manifest disagrees with image version/architecture: {manifest}")
                check(pkg.is_file(), f"embedded package {pkg_name} listed in manifest but missing in image {image}")
                want = sha256sums_lookup((agents / "SHA256SUMS").read_text(), pkg_name)
                got = sha256_bytes(pkg.read_bytes())
                check(want == got, f"SHA256SUMS mismatch for {pkg_name}: manifest {want} != actual {got}")
                check(got == sha256_bytes(raw.read_bytes()), "embedded package differs from image executable")
                log(f"embedded package verified: {pkg_name} sha256={got[:16]}… (manifest keys: {sorted(manifest) if isinstance(manifest, dict) else 'list'})")
                return pkg, got, f"embedded {AGENTS_DIR}/{pkg_name}"
            raise TestFailure(f"required embedded agent package missing in image {image}")
        finally:
            sh(["docker", "rm", "-f", "-v", cname], timeout=60, check=False, quiet=True)

    def run_detached(self, name, image, args, volumes=(), restart=None):
        argv = ["docker", "run", "-d", "--init", "--name", name, "--network", "host"]
        if restart:
            argv += ["--restart", restart]
        for vol in volumes:
            argv += ["-v", vol]
        argv += [image] + list(args)
        sh(argv, timeout=180)
        return name

    def exec(self, container, args, *, check=True, timeout=60):
        return sh(["docker", "exec", container] + list(args), timeout=timeout, check=check, quiet=True)

    def digest_of(self, container, path):
        r = self.exec(container, ["sha256sum", path], check=False)
        if r.returncode != 0:
            return None
        return r.stdout.split()[0].lower() if r.stdout.split() else None

    def path_missing(self, container, path):
        result = self.exec(container, ["test", "-e", path], check=False)
        # Failed docker exec is not evidence that a rollback marker was cleared.
        return result.returncode == 1 and not result.stderr

    def logs(self, container, tail="80"):
        result = sh(["docker", "logs", "--tail", str(tail), container], timeout=60,
                    check=False, quiet=True)
        return (result.stdout or "") + (result.stderr or "")

    def cleanup(self, resources):
        for kind, name in resources:
            if kind == "container":
                sh(["docker", "rm", "-f", "-v", name], timeout=60, check=False, quiet=True)
            elif kind == "volume":
                sh(["docker", "volume", "rm", "-f", name], timeout=60, check=False, quiet=True)
        log(f"cleaned up {len(resources)} unique resource(s)")


# ---------------------------------------------------------------------------
# Hub REST client (stdlib urllib; secrets only ever in request bodies)


class Hub:
    def __init__(self, ca_file, port=HUB_PORT):
        self.ctx = ssl.create_default_context(cafile=str(ca_file))
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=self.ctx))
        self.base = f"https://127.0.0.1:{port}"
        self.token = None

    def request(self, method, path, *, data=None, json_body=None, extra_headers=None, timeout=30):
        if json_body is not None:
            data = json.dumps(json_body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method)
        if json_body is not None:
            req.add_header("content-type", "application/json")
        if self.token:
            req.add_header("authorization", f"Bearer {self.token}")
        for k, v in (extra_headers or {}).items():
            req.add_header(k, v)
        try:
            with self.opener.open(req, timeout=timeout) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()
        except (urllib.error.URLError, OSError, TimeoutError):
            return None, b""

    def json(self, method, path, **kw) -> tuple[int | None, dict[str, Any]]:
        status, body = self.request(method, path, **kw)
        if status is None:
            return None, {}
        try:
            return status, json.loads(body or b"{}")
        except json.JSONDecodeError:
            return status, {"_raw": body.decode(errors="replace")}

    def healthy(self):
        status, _ = self.request("GET", "/healthz", timeout=5)
        return status == 200

    def login(self, secret_key):
        status, body = self.json("POST", "/v0/auth/login", json_body={"secret_key": secret_key})
        check(status == 200, f"hub login failed: {status} {body}")
        self.token = body.get("token")
        check(bool(self.token), "hub login returned no token")
        return self.token

    def create_register_token(self):
        status, body = self.json("POST", "/v0/nodes/register-tokens", json_body={})
        check(status == 200, f"register token creation failed: {status} {body}")
        return body["token"]

    def node(self, node_id):
        status, body = self.json("GET", "/v0/nodes")
        if status != 200:
            return None
        for n in body.get("nodes", []):
            if n.get("id") == node_id:
                return n
        return None

    def node_ready(self, node_id, want_version, after_seen=None):
        n = self.node(node_id)
        if not n or not n.get("online") or n.get("version") != want_version:
            return None
        if after_seen is not None and n.get("last_seen", 0) <= after_seen:
            return None
        return n

    def upload(self, key, artifact, sig_b64, *, expect=200):
        status, body = self.json(
            "POST", "/v0/upgrades", data=artifact,
            extra_headers={"x-rooster-version": key, "x-rooster-signature": sig_b64},
        )
        check(status == expect,
              f"upload {key}: expected HTTP {expect}, got {status} {body}")
        return body

    def upgrade_versions(self):
        status, body = self.json("GET", "/v0/upgrades")
        return {u.get("version") for u in body.get("upgrades", [])} if status == 200 else set()

    def rollout(self, key, node_id):
        status, body = self.json("POST", f"/v0/upgrades/{key}/rollout",
                                 json_body={"node_id": node_id, "batch_size": 1, "wait_secs": 45})
        check(status == 200, f"rollout {key} failed: {status} {body}")
        return body

    def rollout_upgraded(self, run_id, node_id):
        status, body = self.json("GET", f"/v0/rollouts/{run_id}")
        return status == 200 and body.get("status") == "done" and any(
            row.get("node_id") == node_id and row.get("status") == "upgraded"
            for row in body.get("results", [])
        )


# ---------------------------------------------------------------------------
# Offline material: TLS CA/server cert + Ed25519 upgrade signer


def openssl(args, timeout=60):
    # Certificate constraints are explicit below, independent of the host's openssl.cnf.
    return sh(["openssl"] + args, timeout=timeout, env={"OPENSSL_CONF": os.devnull})


def provision(workdir):
    tls = workdir / "tls"
    tls.mkdir()
    ca_key, ca_crt = tls / "ca.key", tls / "ca.crt"
    srv_key, srv_csr, srv_crt = tls / "hub.key", tls / "hub.csr", tls / "hub.crt"
    for p in (ca_key, srv_key):
        p.touch(mode=0o600, exist_ok=True)
        os.chmod(p, 0o600)
    openssl(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
             "-nodes", "-subj", "/CN=rooster-e2e-ca", "-days", "2",
             "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign",
             "-keyout", str(ca_key), "-out", str(ca_crt)])
    openssl(["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
             "-out", str(srv_key)])
    os.chmod(srv_key, 0o600)
    openssl(["req", "-new", "-key", str(srv_key), "-subj", "/CN=127.0.0.1",
             "-out", str(srv_csr)])
    san_file = tls / "san.cnf"
    san_file.write_text("subjectAltName=IP:127.0.0.1,DNS:localhost\n"
                        "basicConstraints=critical,CA:FALSE\n"
                        "keyUsage=critical,digitalSignature\n"
                        "extendedKeyUsage=serverAuth\n")
    openssl(["x509", "-req", "-in", str(srv_csr), "-CA", str(ca_crt), "-CAkey", str(ca_key),
             "-CAcreateserial", "-days", "2", "-extfile", str(san_file), "-out", str(srv_crt)])

    signer = workdir / "upgrade-signing.key"
    signer.touch(mode=0o600, exist_ok=True)
    os.chmod(signer, 0o600)
    openssl(["genpkey", "-algorithm", "ed25519", "-out", str(signer)])
    return {"tls_dir": tls, "ca_crt": ca_crt, "srv_crt": srv_crt, "srv_key": srv_key, "signer": signer}


def ed25519_public(signer_key):
    der_file = signer_key.with_suffix(".pub.der")
    openssl(["pkey", "-in", str(signer_key), "-pubout", "-outform", "DER", "-out", str(der_file)])
    return "ed25519:" + ed25519_public_b64(der_file.read_bytes())


def sign_payload(signer_key, payload_file):
    sig_file = payload_file.with_suffix(".sig")
    openssl(["pkeyutl", "-sign", "-rawin", "-inkey", str(signer_key), "-in", str(payload_file),
             "-out", str(sig_file)], timeout=120)
    sig = sig_file.read_bytes()
    check(len(sig) == 64, f"ed25519 signature must be 64 raw bytes, got {len(sig)}")
    return base64.b64encode(sig).decode()


# ---------------------------------------------------------------------------
# E2E flow


def main(argv=None):
    ap = argparse.ArgumentParser(description="Real Docker signed-upgrade end-to-end validation for rooster")
    ap.add_argument("--old-image", required=True, help="prebuilt image whose agent reports the old version")
    ap.add_argument("--new-image", required=True, help="prebuilt image (same code, new ROOSTER_VERSION) providing the upgrade artifact")
    ap.add_argument("--hub-image", help="image for the hub container (default: --old-image)")
    ap.add_argument("--timeout", type=float, default=300.0, help="per-wait timeout in seconds (default 300)")
    ap.add_argument("--corrupt-timeout", type=float, default=420.0,
                    help="timeout for the corrupt-payload guard rollback incl. 90s grace (default 420)")
    ap.add_argument("--arch", help="architecture suffix for artifact keys (default: docker server arch)")
    ap.add_argument("--port", type=int, help="free host TLS port (default: choose an unused loopback port)")
    ap.add_argument("--keep", action="store_true", help="keep containers/volumes/tmpdir for debugging")
    ap.add_argument("--skip-corrupt", action="store_true", help="skip the corrupt-payload guard-rollback case")
    args = ap.parse_args(argv)
    if args.port is None:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            args.port = probe.getsockname()[1]

    os.umask(0o077)
    run = uuid.uuid4().hex[:8]
    suffix = f"e2e-{run}"
    hub_c, agent_c = f"rooster-{suffix}-hub", f"rooster-{suffix}-agent"
    hub_vol, agent_vol = f"rooster-{suffix}-hubdata", f"rooster-{suffix}-agentdata"
    resources = []
    workdir = Path(tempfile.mkdtemp(prefix=f"rooster-{suffix}-"))
    secret_values = []  # never printed
    dk = None

    def fail_diag(msg):
        if dk:
            for c in (hub_c, agent_c):
                if any(k == "container" and n == c for k, n in resources):
                    log(f"--- docker logs {c} (redacted) ---\n{redact(dk.logs(c), secret_values)}")
        log(f"FAIL: {msg}")

    try:
        dk = Docker()
        arch = args.arch or {"amd64": "x86_64", "arm64": "aarch64"}.get(dk.server_arch, dk.server_arch)
        for img in {args.old_image, args.new_image}:
            if not dk.has_image(img):
                raise EnvError(f"image not present locally: {img} (this script does not build images)")
        old_ver = dk.image_version(args.old_image)
        new_ver = dk.image_version(args.new_image)
        log(f"old-image {args.old_image} reports {old_ver}; new-image {args.new_image} reports {new_ver}")
        ensure_distinct_versions(old_ver, new_ver)
        key_new = artifact_key(new_ver, arch)
        check(node_version(key_new, arch) == new_ver, "artifact key/arch round-trip failed")

        # --- artifacts (embedded package dir when present, else raw binary) ---
        old_pkg, old_digest, old_src = dk.extract_artifact(args.old_image, old_ver, arch, workdir, "old")
        new_pkg, new_digest, new_src = dk.extract_artifact(args.new_image, new_ver, arch, workdir, "new")
        log(f"artifact(old) {old_src} sha256={old_digest}")
        log(f"artifact(new) {new_src} sha256={new_digest}")

        # --- offline PKI + signer + configs ---
        mat = provision(workdir)
        upgrade_pk = ed25519_public(mat["signer"])
        hub_secret = pysecrets.token_hex(24)
        secret_values.extend([hub_secret, upgrade_pk])
        hub_dir = workdir / "hubetc"
        (hub_dir / "tls").mkdir(parents=True)
        for f in ("ca.crt", "hub.crt", "hub.key"):
            (hub_dir / "tls" / f).write_bytes((mat["tls_dir"] / f).read_bytes())
            os.chmod(hub_dir / "tls" / f, 0o600)
        (hub_dir / "hub.yaml").write_text(
            "listen: 127.0.0.1:%d\n"
            "data-dir: /var/lib/rooster-hub\n"
            "public-url: https://127.0.0.1:%d\n"
            "tls:\n"
            "  mode: static\n"
            "  cert: /etc/rooster/tls/hub.crt\n"
            "  key: /etc/rooster/tls/hub.key\n"
            "  ca: /etc/rooster/tls/ca.crt\n"
            "secret-key: %s\n"
            "session-ttl: 24h\n"
            "auto-confirm-delay-secs: 10\n"
            'upgrade-public-key: "%s"\n' % (args.port, args.port, hub_secret, upgrade_pk)
        )
        os.chmod(hub_dir / "hub.yaml", 0o600)

        node_id = f"e2e-node-{run}"
        agent_dir = workdir / "agentetc"
        agent_dir.mkdir()
        (agent_dir / "hub-ca.crt").write_bytes(mat["ca_crt"].read_bytes())

        # --- start hub ---
        resources += [("container", hub_c), ("container", agent_c),
                      ("volume", hub_vol), ("volume", agent_vol)]
        dk.run_detached(hub_c, args.hub_image or args.old_image,
                        ["hub", "--config", "/etc/rooster/hub.yaml"],
                        volumes=[f"{hub_dir}:/etc/rooster", f"{hub_vol}:/var/lib/rooster-hub"])
        hub = Hub(mat["ca_crt"], args.port)
        wait_until("hub /healthz over TLS", hub.healthy, args.timeout)
        log("hub is up (tls static, generated CA, SAN 127.0.0.1)")

        hub.login(hub_secret)
        reg_token = hub.create_register_token()
        secret_values.append(reg_token)
        (agent_dir / "config.yaml").write_text(
            "local:\n"
            "  agent:\n"
            f"    node-name: {node_id}\n"
            "    data-dir: /var/lib/rooster\n"
            "  hub:\n"
            "    url: wss://127.0.0.1:%d\n"
            "    token: %s\n"
            "    ca: /etc/rooster/hub-ca.crt\n"
            "  security:\n"
            '    upgrade-public-key: "%s"\n'
            "  upgrade:\n"
            "    method: exit\n" % (args.port, reg_token, upgrade_pk)
        )
        os.chmod(agent_dir / "config.yaml", 0o600)

        def start_agent(name=agent_c):
            dk.run_detached(name, args.old_image, ["agent"],
                            volumes=[f"{agent_dir}:/etc/rooster:ro", f"{agent_vol}:{AGENT_DATA}"],
                            restart="unless-stopped")

        # --- start agent (old) and enroll via register token in its config ---
        start_agent()
        # A restart policy must observe a stable initial process before testing an upgrade.
        node = wait_until(
            f"agent {node_id} online reporting OLD version {old_ver}",
            lambda: hub.node_ready(node_id, old_ver), args.timeout,
        )
        log(f"agent enrolled via register token: online, version={node['version']} config_hash={node.get('config_hash','-')[:12]}…")
        cert_before = dk.digest_of(agent_c, AGENT_CERT)
        check(cert_before, "cannot digest agent identity cert")
        check(dk.digest_of(agent_c, MUTABLE_BIN) == old_digest,
              "agent mutable binary digest does not match old-image artifact before upgrade")

        time.sleep(10)

        # --- negative: bad signature upload must be rejected, nothing changes ---
        tampered = bytearray(new_pkg.read_bytes())
        tampered[-1] ^= 0xFF
        bad_sig = sign_payload(mat["signer"], new_pkg)
        hub.upload(artifact_key(new_ver + "-badsig", arch), bytes(tampered), bad_sig, expect=422)
        check(artifact_key(new_ver + "-badsig", arch) not in hub.upgrade_versions(),
              "hub stored an artifact whose signature did not verify")
        check(hub.node_ready(node_id, old_ver), "node left old version after rejected upload")
        check(dk.digest_of(agent_c, MUTABLE_BIN) == old_digest,
              "agent binary changed after rejected upload")
        log("bad-signature upload rejected (422); binary unchanged")

        # --- positive: signed upload + targeted rollout ---
        sig_b64 = sign_payload(mat["signer"], new_pkg)
        hub.upload(key_new, new_pkg.read_bytes(), sig_b64)
        check(key_new in hub.upgrade_versions(), "signed upload not listed")
        rollout = hub.rollout(key_new, node_id)
        log(f"rollout issued for {key_new} (node_id={node_id}, batch_size=1, wait_secs=45)")
        node = wait_until(f"agent back online reporting NEW version {new_ver}",
                          lambda: hub.node_ready(node_id, new_ver), args.timeout)
        log(f"upgrade reported by hub: version={node['version']}")

        # --- filesystem + identity assertions ---
        check(dk.digest_of(agent_c, MUTABLE_BIN) == new_digest,
              "upgraded binary digest != uploaded artifact digest")
        check(dk.digest_of(agent_c, MUTABLE_BIN + ".prev") == old_digest,
              "rooster.prev backup digest != old-image artifact digest")
        wait_until("successful upgrade self-check clears marker",
                   lambda: dk.path_missing(agent_c, UPGRADE_MARKER), args.timeout)
        check(dk.digest_of(agent_c, AGENT_CERT) == cert_before,
              "agent identity cert changed across the upgrade")
        check(hub.node_ready(node_id, new_ver), "node identity/version changed after upgrade")
        wait_until("Hub rollout confirms upgraded",
                   lambda: hub.rollout_upgraded(rollout["run_id"], node_id), args.timeout)
        log("post-upgrade asserts OK: digest/backup/marker/identity/rollout")

        # --- corrupt-but-correctly-signed payload -> real guard rollback ---
        if not args.skip_corrupt:
            corrupt = workdir / "corrupt.bin"
            corrupt.write_bytes(pysecrets.token_bytes(8192))
            ckey = artifact_key(f"corrupt-{run}", arch)
            csig = sign_payload(mat["signer"], corrupt)
            hub.upload(ckey, corrupt.read_bytes(), csig)
            hub.rollout(ckey, node_id)
            log(f"corrupt payload rollout issued ({ckey}); expecting crash-loop then guard rollback after 90s grace")
            corrupt_digest = sha256_bytes(corrupt.read_bytes())
            def installed_digest():
                # docker exec may be unavailable while the corrupt process crash-loops.
                copy = workdir / "installed.bin"
                result = sh(["docker", "cp", f"{agent_c}:{MUTABLE_BIN}", str(copy)],
                            check=False, quiet=True)
                return sha256_bytes(copy.read_bytes()) if result.returncode == 0 else None
            wait_until("corrupt signed binary is actually installed",
                       lambda: installed_digest() == corrupt_digest, args.timeout, interval=0.5)
            node = wait_until(
                "guard rollback recovered the NEW version after corrupt rollout",
                lambda: hub.node_ready(node_id, new_ver) if installed_digest() == new_digest else None,
                args.corrupt_timeout, interval=5.0,
            )
            check(dk.digest_of(agent_c, MUTABLE_BIN) == new_digest,
                  "binary digest after guard rollback != new artifact digest")
            wait_until("guard rollback clears marker",
                       lambda: dk.path_missing(agent_c, UPGRADE_MARKER), args.timeout)
            log("guard rollback verified: recovered version=%s digest==artifact" % node["version"])

        # --- recreate container, keep named volume -> still new version ---
        before_recreate = hub.node_ready(node_id, new_ver)
        if before_recreate is None:
            raise TestFailure("agent must be online before recreation")
        last_seen = before_recreate["last_seen"]
        sh(["docker", "rm", "-f", "-v", agent_c], timeout=60, check=False, quiet=True)
        start_agent()
        node = wait_until("recreated agent reconnects on new version",
                          lambda: hub.node_ready(node_id, new_ver, after_seen=last_seen), args.timeout)
        check(dk.digest_of(agent_c, AGENT_CERT) == cert_before,
              "agent identity changed after container recreation")
        check(dk.digest_of(agent_c, MUTABLE_BIN) == new_digest,
              "binary digest changed after container recreation (volume not retained?)")
        log(f"recreated container keeps named volume {agent_vol}: version={node['version']}")

        log(f"PASS: signed docker upgrade E2E old={old_ver} -> new={new_ver} ({old_src} → {new_src}, arch={arch})")
        return 0
    except TestFailure as e:
        fail_diag(redact(str(e), secret_values))
        return 1
    except EnvError as e:
        log(f"ENVIRONMENT ERROR: {e}")
        return 2
    finally:
        if args.keep:
            log(f"--keep: containers={[n for k, n in resources if k == 'container']} "
                f"volumes={[n for k, n in resources if k == 'volume']} workdir={workdir}")
        else:
            if dk:
                dk.cleanup(resources)
            shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())

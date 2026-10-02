import contextlib
import http.server
import os
from pathlib import Path
import shlex
import ssl
import subprocess
import tempfile
import threading
import unittest


ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy.sh"


def bash(body, answers="", cwd=ROOT, env=None):
    return subprocess.run(
        ["bash", "-c", f"source {shlex.quote(str(DEPLOY))}\n{body}"],
        input=answers, text=True, capture_output=True, cwd=cwd,
        env={**os.environ, **(env or {})}, timeout=20,
        # no controlling terminal: prompts fall back from /dev/tty to stdin
        start_new_session=True,
    )


@contextlib.contextmanager
def endpoint(status=200, body=b"ok", cert=None, key=None):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(status if self.path == "/healthz" else 404)
            self.end_headers()
            self.wfile.write(body)

        def handle(self):
            try:
                super().handle()
            except (BrokenPipeError, ConnectionResetError):
                # Hostname rejection can close the TLS socket before an HTTP request.
                pass

        def log_message(self, format, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    if cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


DOCKER = r'''
have(){ return 0; }
detect_ip(){ echo 10.0.0.2; }
docker(){
  printf '%s\n' "$*" >> "$COMMAND_LOG"
  case "$1" in ps) printf '%s' "${EXISTING_CONTAINER:-}";; esac
}
curl(){
  printf '%s\n' "$*" >> "$COMMAND_LOG"
  [ "${FAIL_COMPOSE_DOWNLOAD:-}" != yes ] || return 22
  local url="" output=""
  while [ "$#" -gt 0 ]; do
    case "$1" in
      -o) output="$2"; shift 2;;
      https://*|http://*) url="$1"; shift;;
      *) shift;;
    esac
  done
  cp "$COMPOSE_ROOT/${url##*/}" "$output"
}
wait_hub(){ printf 'PROBE <%s> <%s> <%s> <%s>\n' "$@"; }
'''

NATIVE = r'''
have(){ return 0; }
detect_ip(){ echo 10.0.0.2; }
npm(){
  [ "$1 $2 $3" = '--prefix web ci' ]
  touch dependencies-installed
}
make(){ test -f dependencies-installed; }
as_root(){
  local cmd="$1" arg
  shift
  local -a args=()
  for arg in "$@"; do
    case "$arg" in
      /etc/*|/usr/*|/var/*) args+=("$SANDBOX$arg");;
      *) args+=("$arg");;
    esac
  done
  if [ "$cmd" = systemctl ]; then
    printf '%s\n' "$*" >> "$COMMAND_LOG"
  else
    if [ "$cmd" = tee ]; then mkdir -p "$(dirname "${args[0]}")"; fi
    command "$cmd" "${args[@]}"
  fi
}
wait_hub(){
  test -f "$SANDBOX/usr/share/rooster/web/dist/index.html"
  printf 'PROBE <%s> <%s> <%s> <%s>\n' "$@"
}
'''


class DeployTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)
        self.env = {
            "SANDBOX": str(self.dir / "system"),
            "COMMAND_LOG": str(self.dir / "commands.log"),
            "COMPOSE_ROOT": str(ROOT),
        }

    def ok(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout

    def certificates(self, host="hub.example"):
        tls = self.dir / "certificates"
        self.ok(bash('gen_tls "$TLS" "$HOST"', env={
            "TLS": str(tls), "HOST": host,
        }))
        return tls

    def test_menu_dispatches_each_selected_action(self):
        mocks = "\n".join(
            f"{name}() {{ echo ACTION_{index}; }}"
            for index, name in enumerate([
                "deploy_hub_docker", "deploy_hub_native",
                "deploy_agent_join", "deploy_agent_docker",
            ], 1)
        )
        for index in range(1, 5):
            with self.subTest(choice=index):
                result = bash(mocks + "\nmenu", f"{index}\n")
                self.assertIn(f"ACTION_{index}", self.ok(result))
                self.assertIn("what do you want to deploy?", result.stderr)

    def test_menu_retries_invalid_choice(self):
        result = bash('choice=$(choose test first second); printf "<%s>" "$choice"', "x\n3\n2\n")
        self.assertEqual(self.ok(result), "<second>")
        self.assertIn("invalid choice", result.stderr)

    def test_public_ip_certificate_verifies(self):
        tls = self.certificates("203.0.113.10")
        result = subprocess.run([
            "openssl", "verify", "-CAfile", str(tls / "ca.crt"),
            "-verify_ip", "203.0.113.10", str(tls / "hub.crt"),
        ], text=True, capture_output=True)
        self.ok(result)

    def test_numeric_hostname_is_not_treated_as_ip(self):
        tls = self.certificates("1a.2b.3c.4d")
        result = subprocess.run([
            "openssl", "verify", "-CAfile", str(tls / "ca.crt"),
            "-verify_hostname", "1a.2b.3c.4d", str(tls / "hub.crt"),
        ], text=True, capture_output=True)
        self.ok(result)

    def test_hostname_list_covers_every_entry(self):
        tls = self.certificates("hub.example,forward.example,10.9.9.9")
        for flag, value in [
            ("-verify_hostname", "hub.example"),
            ("-verify_hostname", "forward.example"),
            ("-verify_ip", "10.9.9.9"),
        ]:
            result = subprocess.run([
                "openssl", "verify", "-CAfile", str(tls / "ca.crt"),
                flag, value, str(tls / "hub.crt"),
            ], text=True, capture_output=True)
            self.ok(result)

    def test_health_requires_success_status_and_body(self):
        for status, body, success in [(200, b"ok", True), (502, b"ok", False), (200, b"wrong service", False)]:
            with self.subTest(status=status, body=body), endpoint(status, body) as port:
                result = bash(f'sleep(){{ :; }}; wait_hub {port} plain unused ""')
                self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
                self.assertEqual("hub is up." in result.stdout, success)

    def test_tls_health_checks_hostname_with_custom_or_system_ca(self):
        tls = self.certificates()
        with endpoint(cert=tls / "hub.crt", key=tls / "hub.key") as port:
            for custom in (True, False):
                with self.subTest(custom_ca=custom):
                    ca = str(tls / "ca.crt") if custom else ""
                    env = {} if custom else {"CURL_CA_BUNDLE": str(tls / "ca.crt")}
                    self.ok(bash(f'wait_hub {port} static hub.example {shlex.quote(ca)}', env=env))
            result = bash(f'sleep(){{ :; }}; wait_hub {port} static wrong.example "$CA"', env={"CA": str(tls / "ca.crt")})
            self.assertNotEqual(result.returncode, 0)

    def test_abort_does_not_change_existing_config_or_ca(self):
        config = self.dir / "existing"
        (config / "tls").mkdir(parents=True)
        for path in (config / "hub.yaml", config / "tls/ca.crt"):
            path.write_text("old-deployment")
        answers = f"hub.example\n9443\ntest-only\n{config}\n1\n"
        result = bash(DOCKER + "\ndeploy_hub_docker", answers, env={
            **self.env, "EXISTING_CONTAINER": "rooster-hub\n",
        })
        self.assertNotEqual(result.returncode, 0)
        for path in (config / "hub.yaml", config / "tls/ca.crt"):
            self.assertEqual(path.read_text(), "old-deployment")
        self.assertNotIn("rm -f", Path(self.env["COMMAND_LOG"]).read_text())

    def test_existing_config_is_retained_and_backed_up_during_overwrite(self):
        config = self.dir / "existing"
        config.mkdir()
        (config / "hub.yaml").write_text("old-deployment")
        result = bash(DOCKER + "\ndeploy_hub_docker", f"hub.example\n9443\ntest-only\n{config}\n", env=self.env)
        self.ok(result)
        self.assertEqual((config / "hub.yaml").read_text(), "old-deployment")
        backups = list(config.glob("install-backup.*"))
        self.assertEqual((backups[0] / "hub.yaml").read_text(), "old-deployment")

    def test_docker_tls_uses_port_mapping_and_public_ca_mode(self):
        tls = self.certificates()
        config = self.dir / "docker config"
        answers = f"hub.example\n10443\ntest-only\n{config}\n2\n{tls / 'hub.crt'}\n{tls / 'hub.key'}\n\n"
        output = self.ok(bash(DOCKER + "\ndeploy_hub_docker", answers, env=self.env))
        self.assertIn("PROBE <10443> <static> <hub.example> <>", output)
        self.assertIn("listen: 0.0.0.0:9443", (config / "hub.yaml").read_text())
        self.assertNotIn("  ca:", (config / "hub.yaml").read_text())
        commands = Path(self.env["COMMAND_LOG"]).read_text()
        self.assertIn("/main/compose.yaml", commands)
        self.assertRegex(commands, r"compose --project-directory /\S+ config --quiet")
        self.assertRegex(commands, r"compose --project-directory /\S+ pull")
        self.assertIn(f"compose --project-directory {config} up -d", commands)
        self.assertEqual((config / "compose.yaml").read_text(), (ROOT / "compose.yaml").read_text())
        self.assertIn("ROOSTER_PORT=10443", (config / ".env").read_text())
        self.assertIn("docker compose down", output)
        self.assertNotIn("run -d", commands)

    def test_docker_custom_ca_is_copied_and_used_for_tls_probe(self):
        tls = self.certificates()
        config = self.dir / "private-ca"
        answers = f"hub.example\n10443\ntest-only\n{config}\n2\n{tls / 'hub.crt'}\n{tls / 'hub.key'}\n{tls / 'ca.crt'}\n"
        output = self.ok(bash(DOCKER + "\ndeploy_hub_docker", answers, env=self.env))
        self.assertEqual((config / "tls/ca.crt").read_bytes(), (tls / "ca.crt").read_bytes())
        self.assertIn("  ca: /etc/rooster/tls/ca.crt", (config / "hub.yaml").read_text())
        self.assertIn(f"PROBE <10443> <static> <hub.example> <{config / 'tls/ca.crt'}>", output)

    def test_docker_nginx_uses_requested_backend_and_public_ports(self):
        config = self.dir / "plain"
        answers = f"hub.example\n10443\ntest-only\n{config}\n3\n8443\n"
        output = self.ok(bash(DOCKER + "\ndeploy_hub_docker", answers, env=self.env))
        self.assertIn("listen: 127.0.0.1:10443", (config / "hub.yaml").read_text())
        self.assertIn('public-url: "https://hub.example:8443"', (config / "hub.yaml").read_text())
        self.assertIn("PROBE <10443> <plain>", output)
        self.assertIn("listen 8443 ssl;", output)
        self.assertIn("proxy_pass http://127.0.0.1:10443;", output)
        commands = Path(self.env["COMMAND_LOG"]).read_text()
        self.assertIn("/main/compose.host.yaml", commands)
        self.assertEqual((config / "compose.yaml").read_text(), (ROOT / "compose.host.yaml").read_text())
        self.assertIn("network_mode: host", (config / "compose.yaml").read_text())
        self.assertNotIn("ports:", (config / "compose.yaml").read_text())

    def test_failed_compose_download_keeps_existing_container(self):
        config = self.dir / "failed-download"
        answers = f"hub.example\n9443\ntest-only\n{config}\n2\n1\n"
        result = bash(DOCKER + "\ndeploy_hub_docker", answers, env={
            **self.env, "EXISTING_CONTAINER": "rooster-hub\n",
            "FAIL_COMPOSE_DOWNLOAD": "yes",
        })
        self.assertNotEqual(result.returncode, 0)
        commands = Path(self.env["COMMAND_LOG"]).read_text()
        self.assertNotIn("rm -f", commands)
        self.assertNotIn("up -d", commands)
        self.assertFalse(config.exists())
        retry = bash(DOCKER + "\ndeploy_hub_docker", answers, env={
            **self.env, "EXISTING_CONTAINER": "rooster-hub\n",
        })
        self.ok(retry)

    def test_existing_compose_files_are_backed_up_before_overwrite(self):
        for filename in ("compose.yaml", ".env"):
            with self.subTest(filename=filename):
                config = self.dir / filename.replace(".", "_")
                config.mkdir()
                (config / filename).write_text("existing-settings")
                result = bash(DOCKER + "\ndeploy_hub_docker", f"hub.example\n9443\ntest-only\n{config}\n1\n", env=self.env)
                self.ok(result)
                backups = list(config.glob("install-backup.*"))
                self.assertEqual((backups[0] / filename).read_text(), "existing-settings")
                self.assertNotEqual((config / filename).read_text(), "existing-settings")

    def test_plain_overwrite_retains_backend_port_and_ca(self):
        config = self.dir / "existing-plain"
        config.mkdir()
        old = 'listen: 127.0.0.1:10443\ntls:\n  mode: none\npublic-url: https://hub.example:8443\n'
        (config / "hub.yaml").write_text(old)
        answers = f"hub.example\n9443\ntest-only\n{config}\n8443\n"
        output = self.ok(bash(DOCKER + "\ndeploy_hub_docker", answers, env=self.env))
        self.assertIn("PROBE <10443> <plain>", output)
        self.assertEqual((config / "hub.yaml").read_text(), old)
        self.assertEqual((config / "compose.yaml").read_text(), (ROOT / "compose.host.yaml").read_text())

    def native_workspace(self):
        work = self.dir / "source"
        (work / "web/dist").mkdir(parents=True)
        (work / "web/dist/index.html").write_text("panel-from-build")
        (work / "target/release").mkdir(parents=True)
        (work / "target/release/rooster").write_text("test-binary")
        (work / "Cargo.toml").touch()
        return work

    def test_native_installs_staged_tls_panel_and_custom_port(self):
        work = self.native_workspace()
        answers = "hub.example\n10443\ntest-only\n1\n"
        output = self.ok(bash(NATIVE + "\ndeploy_hub_native", answers, cwd=work, env=self.env))
        system = Path(self.env["SANDBOX"])
        config = system / "etc/rooster/hub.yaml"
        self.assertIn("listen: 0.0.0.0:10443", config.read_text())
        self.assertIn("panel-dir: /usr/share/rooster/web/dist", config.read_text())
        self.assertEqual(config.stat().st_mode & 0o777, 0o600)
        self.assertEqual((system / "usr/share/rooster/web/dist/index.html").read_text(), "panel-from-build")
        self.assertEqual((system / "etc/rooster/tls/hub.key").stat().st_mode & 0o777, 0o600)
        self.assertIn("PROBE <10443> <static>", output)
        self.assertIn("enable rooster-hub", Path(self.env["COMMAND_LOG"]).read_text())
        self.assertIn("restart rooster-hub", Path(self.env["COMMAND_LOG"]).read_text())

    def test_native_nginx_uses_requested_ports_without_installing_tls(self):
        work = self.native_workspace()
        answers = "hub.example\n10443\ntest-only\n3\n8443\n"
        output = self.ok(bash(NATIVE + "\ndeploy_hub_native", answers, cwd=work, env=self.env))
        system = Path(self.env["SANDBOX"])
        config = (system / "etc/rooster/hub.yaml").read_text()
        self.assertIn("listen: 127.0.0.1:10443", config)
        self.assertIn("mode: none", config)
        self.assertFalse((system / "etc/rooster/tls").exists())
        self.assertIn("PROBE <10443> <plain> <hub.example> <>", output)
        self.assertIn("listen 8443 ssl;", output)
        self.assertIn("proxy_pass http://127.0.0.1:10443;", output)

    def test_native_preserves_existing_configuration(self):
        work = self.native_workspace()
        config = Path(self.env["SANDBOX"]) / "etc/rooster/hub.yaml"
        config.parent.mkdir(parents=True)
        old = "listen: 127.0.0.1:10443\ntls:\n  mode: none\n"
        config.write_text(old)
        result = bash(NATIVE + "\ndeploy_hub_native", "hub.example\n10443\ntest-only\n3\n8443\n", cwd=work, env=self.env)
        self.ok(result)
        self.assertEqual(config.read_text(), old)
        backups = list(config.parent.glob("install-backup.*"))
        self.assertEqual((backups[0] / "hub.yaml").read_text(), old)

    def test_agent_unsigned_is_only_enabled_by_explicit_choice(self):
        mocks = r'''
have(){ return 0; }
curl(){
  while [ "$1" != -o ]; do shift; done
  printf 'printf "INSTALL_ARG <%%s>\\n" "$@"\n' > "$2"
}
as_root(){ "$@"; }
'''
        for choice, unsigned in [(1, False), (2, True)]:
            with self.subTest(choice=choice):
                answers = f"https://hub.example:9443\n1\ntest-token\n{choice}\n{'a' * 64}\n"
                output = self.ok(bash(mocks + "\ndeploy_agent_join", answers))
                self.assertEqual("INSTALL_ARG <--allow-unsigned>" in output, unsigned)
                self.assertIn("INSTALL_ARG <--ca-sha256>", output)
                self.assertNotIn("INSTALL_ARG <--insecure>", output)
                self.assertIn("INSTALL_ARG <test-token>", output)

    def test_printed_self_signed_curl_command_has_valid_flags(self):
        output = self.ok(bash("join_hint hub.example 9443 yes"))
        command = next(line.strip() for line in output.splitlines() if line.strip().startswith("curl "))
        flags = shlex.split(command)[1]
        result = subprocess.run(["curl", flags, "--version"], text=True, capture_output=True)
        self.ok(result)


if __name__ == "__main__":
    unittest.main()

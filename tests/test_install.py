import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
INSTALL = (ROOT / 'crates/rooster-hub/src/install.rs').read_text().split('r#"', 1)[1].split('"#', 1)[0].replace('{hub_base}', 'https://hub.example:9443')

MOCK = r'''
id() { echo 0; }
uname() { echo x86_64; }
sleep() { :; }
systemctl() { printf '%s\n' "$*" >> "$LOG"; }
curl() {
  printf 'CURL %s\n' "$*" >> "$LOG"
  case "$*" in
    *readyz*) [ "${NOT_READY:-}" != yes ] || return 22; printf ok; return;;
  esac
  [ "${DOWNLOAD_FAIL:-}" != yes ] || return 22
  while [ "$1" != -o ]; do shift; done
  case "$*" in
    *x86_64.sig*|*pubkey.pem*) printf mock > "$2";;
    *) printf '#!/bin/sh\nexit 0\n' > "$2";;
  esac
}
openssl() {
  case "$1" in
    pkeyutl) [ "${BAD_SIGNATURE:-}" != yes ];;
    *) command openssl "$@";;
  esac
}
'''


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)
        self.env = {**os.environ, 'ROOSTER_BIN_DIR': str(self.dir / 'bin'),
                    'ROOSTER_CONF_DIR': str(self.dir / 'conf'), 'ROOSTER_DATA_DIR': str(self.dir / 'data'),
                    'ROOSTER_UNIT_DIR': str(self.dir / 'unit'), 'LOG': str(self.dir / 'log')}

    def run_install(self, *args, **env):
        return subprocess.run(['sh', '-c', MOCK + INSTALL, 'install.sh', '--token', "token'quoted", *args],
                              env={**self.env, **env}, text=True, capture_output=True, timeout=15)

    def ok(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_overwrite_is_backed_up_and_private_and_restarts(self):
        self.ok(self.run_install('--name', 'node-1'))
        config = self.dir / 'conf/config.yaml'
        old = config.read_text()
        self.assertEqual(config.stat().st_mode & 0o777, 0o600)
        self.assertIn("token: 'token''quoted'", old)
        config.write_text(old + '# retained in backup\n')
        self.ok(self.run_install('--name', 'node-1'))
        backups = list((self.dir / 'conf').glob('install-backup.*'))
        populated = next(path for path in backups if (path / 'config.yaml').exists())
        self.assertIn('retained in backup', (populated / 'config.yaml').read_text())
        self.assertEqual(populated.stat().st_mode & 0o777, 0o700)
        log = (self.dir / 'log').read_text()
        self.assertIn('restart rooster', log)
        self.assertIn('Authorization: Bearer', log)
        self.assertNotIn('enable --now', log)

    def test_download_and_signature_failure_leave_installation_untouched(self):
        for env in ({'DOWNLOAD_FAIL': 'yes'}, {'BAD_SIGNATURE': 'yes'}):
            result = self.run_install('--name', 'node-1', **env)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((self.dir / 'conf').exists())
            self.assertFalse((self.dir / 'bin').exists())

    def test_insecure_and_invalid_name_are_rejected_before_download(self):
        for args in [('--insecure',), ('--name', 'bad name'), ('--hub', 'http://remote.example:9443'), ('--ca-file',)]:
            result = self.run_install(*args)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((self.dir / 'log').exists())

    def test_ca_is_verified_and_copied_privately(self):
        ca = self.dir / 'trusted-ca.crt'
        ca.write_text('test-ca')
        self.ok(self.run_install('--name', 'node-1', '--ca-file', str(ca)))
        installed = self.dir / 'conf/server-ca.crt'
        self.assertEqual(installed.read_text(), 'test-ca')
        self.assertEqual(installed.stat().st_mode & 0o777, 0o600)
        log = (self.dir / 'log').read_text()
        for line in log.splitlines():
            if line.startswith('CURL') and 'readyz' not in line:
                self.assertIn('--cacert', line)
                self.assertNotIn('-k', line)

    def test_real_verification_command_accepts_large_ed25519_and_rejects_tampering(self):
        key, pub = self.dir / 'key.pem', self.dir / 'rooster.pub'
        binary, sig = self.dir / 'rooster.new', self.dir / 'rooster.sig'
        binary.write_bytes(b'x' * (17 * 1024 * 1024))
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(key)], check=True, capture_output=True)
        subprocess.run(['openssl', 'pkey', '-in', str(key), '-pubout', '-out', str(pub)], check=True, capture_output=True)
        subprocess.run(['openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', str(key), '-in', str(binary), '-out', str(sig)], check=True, capture_output=True)
        command = INSTALL.split('  openssl pkeyutl', 1)[1].split(' || fail', 1)[0]
        command = 'openssl pkeyutl' + command
        env = {**os.environ, 'TMP_DIR': str(self.dir)}
        result = subprocess.run(['sh', '-c', command], env=env, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        with binary.open('r+b') as file:
            file.write(b'y')
        result = subprocess.run(['sh', '-c', command], env=env, text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)

    def test_readiness_timeout_is_failure(self):
        result = self.run_install('--name', 'node-1', NOT_READY='yes')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('did not connect', result.stderr)
        self.assertNotIn('installed and connected', result.stdout)
        self.assertEqual((self.dir / 'log').read_text().count('/readyz'), 60)

    def test_existing_identity_cannot_silently_migrate(self):
        self.ok(self.run_install('--name', 'node-1'))
        pki = self.dir / 'data/pki'
        pki.mkdir()
        (pki / 'agent.crt').write_text('existing-identity')
        old = (self.dir / 'conf/config.yaml').read_text()
        result = self.run_install('--name', 'different-node')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.dir / 'conf/config.yaml').read_text(), old)
        self.ok(self.run_install('--name', 'node-1'))
        self.assertEqual((pki / 'agent.crt').read_text(), 'existing-identity')


if __name__ == '__main__':
    unittest.main()

import hashlib
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / 'enroll.sh').read_text()
MOCK = r'''
id() { echo 0; }
curl() {
  printf '%s\n' "$*" >> "$LOG"
  local_output=""
  local_url=""
  while [ "$#" -gt 0 ]; do
    case "$1" in -o) local_output="$2"; shift 2;; https://*) local_url="$1"; shift;; *) shift;; esac
  done
  case "$local_url" in
    */ca.crt) cp "$CA_SOURCE" "$local_output";;
    */install.sh) printf '#!/bin/sh\nprintf "INSTALL_ARG <%%s>\\n" "$@"\n' > "$local_output";;
    *) return 22;;
  esac
}
'''


class EnrollTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)
        self.ca = self.dir / 'ca.crt'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                        '-nodes', '-subj', '/CN=test-ca', '-days', '1', '-keyout', str(self.dir / 'key'),
                        '-out', str(self.ca)], check=True, capture_output=True)
        der = ssl.PEM_cert_to_DER_cert(self.ca.read_text())
        self.fingerprint = hashlib.sha256(der).hexdigest()
        self.log = self.dir / 'log'

    def run_enroll(self, *args):
        return subprocess.run(['sh', '-c', MOCK + SCRIPT, 'enroll.sh', '--hub', 'https://hub.example:9443',
                               '--token', 'test-token', *args], env={**os.environ, 'LOG': str(self.log),
                               'CA_SOURCE': str(self.ca)}, capture_output=True, text=True, timeout=15)

    def test_fingerprint_mismatch_never_downloads_or_executes_installer(self):
        result = self.run_enroll('--ca-sha256', '0' * 64)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('fingerprint mismatch', result.stderr)
        self.assertNotIn('/install.sh', self.log.read_text())
        self.assertNotIn('INSTALL_ARG', result.stdout)

    def test_matching_fingerprint_verifies_installer_connection(self):
        result = self.run_enroll('--ca-sha256', self.fingerprint, '--name', 'node-1')
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = self.log.read_text().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertIn('-kfsSL', lines[0])
        self.assertIn('/ca.crt', lines[0])
        self.assertIn('--cacert', lines[1])
        self.assertNotIn('-k', lines[1])
        self.assertIn('INSTALL_ARG <--ca-file>', result.stdout)
        self.assertIn('INSTALL_ARG <node-1>', result.stdout)

    def test_public_ca_path_never_uses_insecure_downloads(self):
        result = self.run_enroll()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('-k', self.log.read_text())
        self.assertNotIn('/ca.crt', self.log.read_text())

    def test_rejects_old_insecure_option(self):
        result = self.run_enroll('--insecure')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.log.exists())


if __name__ == '__main__':
    unittest.main()

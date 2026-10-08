"""Tests for docker/entrypoint.sh — run with a fake image binary, no Docker.

The fake "immutable binary" records every invocation and emulates the parts of
`rooster` the entrypoint depends on:
  - `agent upgrade-guard --data-dir D --binary B`: optional rollback of
    B <- B.prev + marker cleanup (GUARD_ACTION=rollback), configurable exit
    code (GUARD_RC); without --binary it just exits.
  - the agent daemon: exit code AGENT_RC (default 0).
The mutable binary is a byte copy of the fake (what a real seed produces), so
seeded/persisted/rolled-back states are distinguished by file content.
"""

import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = ROOT / "docker" / "entrypoint.sh"

FAKE_IMAGE_BIN = r"""#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_LOG"
if [ "$1" = agent ] && [ "$2" = upgrade-guard ]; then
  binary=""
  while [ $# -ge 2 ]; do
    case "$1" in
      --binary) binary="$2"; break ;;
      --binary=*) binary="${1#--binary=}"; break ;;
    esac
    shift
  done
  if [ -f "$FAKE_MARKER" ] && [ -n "$binary" ] && [ -f "$binary.prev" ]; then
    cp "$binary.prev" "$binary"
    rm -f "$FAKE_MARKER"
    printf 'ROLLBACK\n' >> "$FAKE_LOG"
  elif [ -f "$FAKE_MARKER" ]; then
    printf 'MARKER-KEPT\n' >> "$FAKE_LOG"
  fi
  exit "${GUARD_RC:-0}"
fi
exit "${AGENT_RC:-0}"
"""

AGENT_GUARD_ARGS = "agent upgrade-guard --data-dir {data} --binary {data}/bin/rooster"


class EntryPointTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)
        self.data = self.dir / "data"
        self.image_bin = self.dir / "image" / "rooster"
        self.image_bin.parent.mkdir(parents=True)
        self.image_bin.write_text(FAKE_IMAGE_BIN)
        self.image_bin.chmod(0o755)
        self.log = self.dir / "invocations.log"

    def run_entrypoint(self, args, guard_rc=None, extra_env=None):
        env = {
            **os.environ,
            "ROOSTER_IMAGE_BINARY": str(self.image_bin),
            "ROOSTER_AGENT_DATA_DIR": str(self.data),
            "FAKE_LOG": str(self.log),
            "FAKE_MARKER": str(self.data / "upgrade-pending.json"),
        }
        if guard_rc is not None:
            env["GUARD_RC"] = str(guard_rc)
        env.update(extra_env or {})
        return subprocess.run(
            ["/bin/sh", str(ENTRYPOINT), *args],
            capture_output=True, text=True, env=env, timeout=20,
        )

    def fresh_state(self, name):
        """Isolate subTest iterations: new data dir + cleared log."""
        self.data = self.dir / ("data-%s" % name)
        if self.log.exists():
            self.log.unlink()

    def invocations(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def agent_bin(self):
        return self.data / "bin" / "rooster"

    def write_marker(self, version="9.9.9"):
        self.data.mkdir(parents=True, exist_ok=True)
        marker = self.data / "upgrade-pending.json"
        marker.write_text('{"version": "%s", "ts": 0}' % version)
        return marker

    # ---- non-agent commands forward directly to the immutable binary -----

    def test_hub_and_toplevel_commands_forward_without_side_effects(self):
        for index, args in enumerate(
            (["hub", "--config", "/etc/rooster/hub.yaml"],
             ["--version"],
             ["hub", "backup", "/tmp/out"]),
        ):
            with self.subTest(args=args):
                self.fresh_state("fwd%d" % index)
                result = self.run_entrypoint(args)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.invocations(), [" ".join(args)])
                self.assertFalse(self.data.exists(), "hub must not touch the agent data dir")

    def test_agent_help_forwards_to_image_binary(self):
        for args in (["agent", "--help"], ["agent", "-h"]):
            with self.subTest(args=args):
                self.fresh_state("help")
                result = self.run_entrypoint(args)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.invocations(), [" ".join(args)])
                self.assertFalse(self.agent_bin().exists(), "help must not seed")

    def test_agent_upgrade_guard_passes_through_verbatim(self):
        other = self.dir / "other-data"
        args = ["agent", "upgrade-guard", "--data-dir", str(other), "--binary", "x"]
        result = self.run_entrypoint(args)
        self.assertEqual(result.returncode, 0, result.stderr)
        # forwarded unchanged: no appended overrides, no guard auto-launch
        self.assertEqual(
            self.invocations(),
            ["agent upgrade-guard --data-dir %s --binary x" % other],
        )
        self.assertFalse(self.data.exists(), "guard pass-through must not seed")

    # ---- seeding + overrides --------------------------------------------

    def test_seeds_mutable_binary_and_execs_with_overrides(self):
        result = self.run_entrypoint(["agent", "--config", "/etc/rooster/config.yaml"])
        self.assertEqual(result.returncode, 0, result.stderr)
        seeded = self.agent_bin()
        self.assertTrue(seeded.is_file())
        self.assertEqual(seeded.read_text(), FAKE_IMAGE_BIN)
        self.assertEqual(seeded.stat().st_mode & 0o777, 0o755)
        self.assertEqual(list((self.data / "bin").glob(".rooster.seed*")), [], "no temp leftovers")
        guard, agent = self.invocations()
        self.assertEqual(guard, AGENT_GUARD_ARGS.format(data=self.data))
        self.assertEqual(
            agent,
            "agent --config /etc/rooster/config.yaml --data-dir %s --upgrade-method exit" % self.data,
        )

    def test_guard_runs_on_every_start_even_with_healthy_binary(self):
        self.data.mkdir(parents=True)
        self.agent_bin().parent.mkdir()
        self.agent_bin().write_text(FAKE_IMAGE_BIN)
        self.agent_bin().chmod(0o755)
        result = self.run_entrypoint(["agent"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.invocations()[0], AGENT_GUARD_ARGS.format(data=self.data))

    def test_persisted_upgraded_binary_survives_restart(self):
        # first start: seeds from the image
        self.assertEqual(self.run_entrypoint(["agent"]).returncode, 0)
        # a hub-signed upgrade replaced the mutable binary, then the agent
        # exited(0) and docker restarted the container
        upgraded = "#!/bin/sh\nprintf 'UPGRADED %s\\n' \"$*\" >> %s\nexit 0\n" % (
            "%s", shlex.quote(str(self.log)))
        self.agent_bin().write_text(upgraded)
        self.agent_bin().chmod(0o755)
        result = self.run_entrypoint(["agent"])
        self.assertEqual(result.returncode, 0, result.stderr)
        # not re-seeded from the image binary, guard still ran
        self.assertEqual(self.agent_bin().read_text(), upgraded)
        invocations = self.invocations()
        self.assertEqual(invocations.count(AGENT_GUARD_ARGS.format(data=self.data)), 2)
        self.assertTrue(invocations[-1].startswith("UPGRADED agent --data-dir %s" % self.data))

    def test_exec_of_persisted_binary_propagates_exit_code(self):
        self.data.mkdir(parents=True)
        self.agent_bin().parent.mkdir()
        self.agent_bin().write_text(
            "#!/bin/sh\nprintf 'MUTABLE %s\\n' \"$*\" >> %s\nexit 7\n"
            % ("%s", shlex.quote(str(self.log)))
        )
        self.agent_bin().chmod(0o755)
        result = self.run_entrypoint(["agent", "--config", "/c.yaml"])
        # exec (not spawn): the entrypoint's exit code IS the agent's
        self.assertEqual(result.returncode, 7)
        self.assertEqual(
            self.invocations()[-1],
            "MUTABLE agent --config /c.yaml --data-dir %s --upgrade-method exit" % self.data,
        )

    # ---- guard failure / pending upgrade ---------------------------------

    def test_guard_failure_rejects_start_and_does_not_seed(self):
        result = self.run_entrypoint(["agent"], guard_rc=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("upgrade-guard failed", result.stderr)
        self.assertEqual(self.invocations(), [AGENT_GUARD_ARGS.format(data=self.data)])
        self.assertFalse(self.agent_bin().exists(), "no seeding after guard failure")

    def test_marker_without_binary_gets_guard_rollback_before_seed(self):
        marker = self.write_marker()
        prev = "#!/bin/sh\nprintf 'RESTORED %s\\n' \"$*\" >> %s\nexit 0\n" % (
            "%s", shlex.quote(str(self.log)))
        (self.data / "bin").mkdir(parents=True)
        (self.data / "bin" / "rooster.prev").write_text(prev)
        (self.data / "bin" / "rooster.prev").chmod(0o755)
        result = self.run_entrypoint(["agent"])
        self.assertEqual(result.returncode, 0, result.stderr)
        # rolled back to .prev (not re-seeded from the image), marker cleared,
        # restored binary ran with the appended overrides
        self.assertEqual(self.agent_bin().read_text(), prev)
        self.assertNotEqual(self.agent_bin().read_text(), FAKE_IMAGE_BIN)
        self.assertFalse(marker.exists())
        invocations = self.invocations()
        self.assertEqual(invocations[0], AGENT_GUARD_ARGS.format(data=self.data))
        self.assertEqual(invocations[1], "ROLLBACK")
        self.assertTrue(invocations[2].startswith("RESTORED agent --data-dir %s" % self.data))

    def test_pending_marker_blocks_seeding(self):
        # guard succeeded but could not clear the marker (e.g. fresh marker,
        # binary vanished): the entrypoint must not seed over the upgrade
        self.write_marker()
        result = self.run_entrypoint(["agent"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing or not executable", result.stderr)
        self.assertEqual(
            self.invocations(),
            [AGENT_GUARD_ARGS.format(data=self.data), "MARKER-KEPT"],
        )
        self.assertFalse(self.agent_bin().exists())

    # ---- CLI override normalization ---------------------------------------

    def test_conflicting_cli_data_dir_is_rejected(self):
        result = self.run_entrypoint(["agent", "--data-dir", "/somewhere-else"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--data-dir", result.stderr)
        self.assertIn(str(self.data), result.stderr)
        self.assertEqual(self.invocations(), [], "nothing may run on conflict")
        self.assertFalse(self.agent_bin().exists())

    def test_matching_cli_data_dir_is_normalized_to_one_flag(self):
        result = self.run_entrypoint(["agent", "--data-dir", str(self.data)])
        self.assertEqual(result.returncode, 0, result.stderr)
        agent_line = self.invocations()[-1]
        self.assertEqual(agent_line.count("--data-dir"), 1)
        self.assertTrue(agent_line.endswith("--data-dir %s --upgrade-method exit" % self.data))

    def test_upgrade_method_only_exit_is_allowed(self):
        for method, ok in (("exit", True), ("systemd", False), ("none", False)):
            with self.subTest(method=method):
                self.fresh_state("method-%s" % method)
                result = self.run_entrypoint(["agent", "--upgrade-method", method])
                self.assertEqual(result.returncode == 0, ok, result.stderr)
                if ok:
                    self.assertEqual(self.invocations()[-1].count("--upgrade-method"), 1)
                else:
                    self.assertIn("--upgrade-method", result.stderr)
                    self.assertEqual(self.invocations(), [])

    def test_equals_form_flags_are_normalized_too(self):
        result = self.run_entrypoint(
            ["agent", "--data-dir=%s" % self.data, "--upgrade-method=exit"]
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        agent_line = self.invocations()[-1]
        self.assertEqual(agent_line.count("--data-dir"), 1)
        self.assertEqual(agent_line.count("--upgrade-method"), 1)

    def test_config_flag_is_preserved_in_place(self):
        result = self.run_entrypoint(["agent", "--config", "/etc/rooster/config.yaml"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(
            self.invocations()[-1].startswith("agent --config /etc/rooster/config.yaml --data-dir")
        )


if __name__ == "__main__":
    unittest.main()

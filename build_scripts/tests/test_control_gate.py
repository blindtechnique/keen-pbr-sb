"""Real flock/SIGKILL checks using the shipped init functions in a private root."""
import os
from pathlib import Path
import re
import select
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]
INIT = REPO / "packages/keenetic/keen-pbr/files/opt/etc/init.d/S80keen-pbr"
STAT = REPO / "packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr/portable-stat.sh"


@unittest.skipUnless(Path("/.dockerenv").exists() and getattr(os, "geteuid", lambda: -1)() == 0,
                     "isolated root Linux container required")
class ControlGateTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="kpbr-gate-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        source = INIT.read_text()
        block = source.split("# Netfilter stop admission marker.", 1)[1].split(
            "# End netfilter stop admission marker", 1)[0]
        metadata = re.search(r"^path_owner_group_mode\(\) \{.*?^}", source, re.M | re.S).group()
        self.script = self.root / "gate.sh"
        self.script.write_text(
            "#!/bin/sh\nset -eu\n" + STAT.read_text() +
            "\nKEEN_PBR_PORTABLE_STAT_LOADED=yes\n" + metadata + "\n" +
            "# Netfilter stop admission marker." + block + "\n" +
            'STOPPING_RUNTIME_DIR="$1/runtime"\n'
            'STOPPING_PROC_ROOT=/proc\n'
            'STOPPING_CONTROL_RECOVERY_GATE_DIR="$STOPPING_RUNTIME_DIR/control-lease-recovery"\n'
            'STOPPING_CONTROL_RECOVERY_GATE_OWNER="$STOPPING_CONTROL_RECOVERY_GATE_DIR/owner"\n'
            'STOPPING_CONTROL_RECOVERY_GATE_MAGIC=keen-pbr-control-recovery-v1\n'
            'log_error() { printf "%s\\n" "$*" >&2; }\n'
            'if [ "${2:-}" = scan ]; then STOPPING_PROC_ROOT="$1/proc"; legacy_control_gate_writer_is_live; exit $?; fi\n'
            'ticks=$(stopping_process_startticks "$$")\n'
            'acquire_control_recovery_gate "$ticks" || exit $?\n'
            'printf "READY\\n"\n'
            '[ "${2:-}" != hold ] || read -r reply\n'
            'release_control_recovery_gate "$ticks"\n')
        # Pre-create the protected parent so the test concerns lock contention,
        # not two processes trying to initialize the runtime directory.
        (self.root / "runtime").mkdir(mode=0o700)

    def invoke(self):
        return subprocess.run(["/bin/busybox", "sh", str(self.script), str(self.root)],
                              capture_output=True, text=True, timeout=10)

    def holder(self):
        proc = subprocess.Popen(["/bin/busybox", "sh", str(self.script), str(self.root), "hold"],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
        self.addCleanup(self.finish, proc)
        ready, _, _ = select.select([proc.stdout], [], [], 10)
        self.assertTrue(ready, "gate owner never reported acquisition")
        self.assertEqual(proc.stdout.readline(), "READY\n")
        return proc

    @staticmethod
    def finish(proc):
        if proc.poll() is None:
            proc.kill()
        proc.communicate(timeout=10)

    def test_live_owner_is_not_displaced_and_sigkill_does_not_brick_next_action(self):
        proc = self.holder()
        owner = self.root / "runtime/control-lease-recovery/owner"
        identity = owner.read_text()
        contender = self.invoke()
        self.assertEqual(contender.returncode, 2, contender.stderr)
        self.assertEqual(owner.read_text(), identity)
        lock = self.root / "runtime/control-recovery.lock"
        inode = lock.stat().st_ino
        proc.kill()
        proc.wait(timeout=10)
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(lock.stat().st_ino, inode)
        self.assertFalse(owner.exists())

    def test_empty_dead_gate_is_reclaimed(self):
        gate = self.root / "runtime/control-lease-recovery"
        gate.mkdir(mode=0o700)
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(gate.exists())

    def test_legacy_writer_detection_does_not_match_inspection_arguments(self):
        command = self.root / "proc/999999/cmdline"
        command.parent.mkdir(parents=True)
        for args, expected in (
            (["/bin/sh", "/opt/etc/init.d/S80keen-pbr", "stop"], 0),
            (["/bin/busybox", "sh", "-e", "/opt/etc/init.d/S80keen-pbr", "stop"], 0),
            (["/bin/sh", "test.sh", "/opt/etc/init.d/S80keen-pbr"], 1),
            (["/bin/cat", "/opt/etc/init.d/S80keen-pbr"], 1),
        ):
            command.write_bytes(b"\0".join(x.encode() for x in args) + b"\0")
            result = subprocess.run(["/bin/busybox", "sh", str(self.script), str(self.root), "scan"],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, expected, result.stderr)

    def test_symlink_gate_cannot_delete_a_foreign_owner(self):
        foreign = self.root / "foreign"
        foreign.mkdir(mode=0o700)
        (foreign / "owner").write_text("untouched\n")
        (self.root / "runtime/control-lease-recovery").symlink_to(foreign)
        self.assertEqual(self.invoke().returncode, 1)
        self.assertEqual((foreign / "owner").read_text(), "untouched\n")


if __name__ == "__main__":
    unittest.main()

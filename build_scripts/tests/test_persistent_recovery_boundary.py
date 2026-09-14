"""Exercise the shipped offline-process boundary with BusyBox sh."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
GUARD = ROOT / "packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr/rescue-startup-guard.sh"
BUSYBOX = os.environ.get("BUSYBOX") or shutil.which("busybox")


@unittest.skipUnless(BUSYBOX, "BusyBox is required")
class PersistentRecoveryBoundaryTest(unittest.TestCase):
    def run_boundary(self, operation, running):
        source = GUARD.read_text(encoding="utf-8")
        start = source.index('managed_processes="')
        end = source.index('\nif [ ! -f "$KEEN_PBR_BINARY"', start)
        with tempfile.TemporaryDirectory() as directory:
            active = Path(directory) / "backup-restore-active"
            if operation == "backup-restore":
                active.touch()
            script = '''
fail() { printf '%s\\n' "$1" >&2; exit 1; }
pidof() { [ "$1" = "$RUNNING_PROCESS" ] && printf '123\\n'; }
''' + source[start:end]
            return subprocess.run(
                [BUSYBOX, "sh", "-c", script],
                env={**os.environ, "BACKUP_RESTORE_ACTIVE": str(active),
                     "RUNNING_PROCESS": running},
                text=True, capture_output=True, timeout=5,
            )

    def test_config_save_leaves_nfqws_running(self):
        for process in ("nfqws", "nfqws2"):
            with self.subTest(process=process):
                result = self.run_boundary("config-save", process)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_backup_restore_still_requires_nfqws_offline(self):
        for process in ("nfqws", "nfqws2"):
            with self.subTest(process=process):
                result = self.run_boundary("backup-restore", process)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(process + " is running", result.stderr)

    def test_config_save_still_requires_its_affected_services_offline(self):
        for process in ("keen-pbr", "transport-manager", "sing-box"):
            with self.subTest(process=process):
                result = self.run_boundary("config-save", process)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(process + " is running", result.stderr)


if __name__ == "__main__":
    unittest.main()

"""Exercise real upgrade capture/init functions entirely below a temporary root."""

import io
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
FILES = ROOT / "packages/keenetic/keen-pbr/files"
RESCUE = FILES / "opt/usr/lib/keen-pbr/rescue-update.sh"
BUSYBOX = shutil.which("busybox")


def function(source, name):
    start = source.index("\n" + name + "() {\n") + 1
    return source[start:source.index("\n}\n", start) + 3]


@unittest.skipUnless(BUSYBOX, "BusyBox is required")
class TransportUpgradeStateTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="kpbr-upgrade-intent-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.opt = self.root / "opt"
        self.rescue = self.opt / "var/lib/keen-pbr/rescue"
        self.config = self.opt / "etc/keen-pbr"
        self.init = self.opt / "etc/init.d"
        self.state = self.rescue / "transport-upgrade-state.json"
        self.events = self.root / "events"
        for directory in (self.rescue, self.config, self.init):
            directory.mkdir(parents=True)
        (self.config / "transports.json").write_text('{"auto_start":true}\n')
        self.executable(self.opt / "usr/bin/transport-manager", 'echo legacy-cli-called >> "$EVENTS"; exit 99')
        self.executable(self.init / "S79transport-manager", 'echo "transport:$1" >> "$EVENTS"; exit 0')
        self.executable(self.init / "S80keen-pbr", 'echo "daemon:$1" >> "$EVENTS"; exit 0')

    def executable(self, path, body):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/sh\n" + body + "\n")
        path.chmod(0o755)

    def run_shell(self, source, *args, **environment):
        return subprocess.run(
            [BUSYBOX, "sh", "-c", source, "test", *args],
            env={**os.environ, "EVENTS": str(self.events), **environment},
            capture_output=True, text=True, timeout=15)

    def package(self, body):
        data = io.BytesIO()
        encoded = ("#!/bin/sh\n" + body + "\n").encode()
        with tarfile.open(fileobj=data, mode="w:gz") as archive:
            member = tarfile.TarInfo("./opt/usr/bin/transport-manager")
            member.size = len(encoded)
            member.mode = 0o755
            archive.addfile(member, io.BytesIO(encoded))
        package = self.rescue / "candidate.ipk"
        with tarfile.open(package, "w:gz") as archive:
            member = tarfile.TarInfo("./data.tar.gz")
            member.size = len(data.getvalue())
            archive.addfile(member, io.BytesIO(data.getvalue()))
        return package

    def capture(self, body, stage=False):
        package = self.package(body)
        source = RESCUE.read_text()
        script = function(source, "capture_candidate_transport_state")
        script += f"""
ROOT='{self.root}'
RESCUE_DIR='{self.rescue}'
CONFIG_DIR='{self.config}'
TRANSPORT_INIT='{self.init / 'S79transport-manager'}'
TRANSPORT_UPGRADE_STATE='{self.state}'
CANDIDATE_IPK='{package}'
tar() {{ '{BUSYBOX}' tar "$@"; }}
"""
        if stage:
            script += function(source, "stage_candidate") + """
CURRENT_IPK="$RESCUE_DIR/no-baseline.ipk"
PENDING_BASELINE_IPK="$RESCUE_DIR/pending-baseline.ipk"
PRE_UPDATE_CONFIG="$RESCUE_DIR/pre-update-config"
ensure_known_idle() { :; }
valid_ipk_payload() { test -f "$1"; }
valid_ipk_file() { return 1; }
cleanup_pending_artifacts() { echo cleanup >> "$EVENTS"; rm -f "$TRANSPORT_UPGRADE_STATE"; }
import_file_from() { :; }
snapshot_config() { :; }
write_pending() { echo pending >> "$EVENTS"; }
stage_candidate "$CANDIDATE_IPK"
"""
        else:
            script += "capture_candidate_transport_state\n"
        return self.run_shell(script)

    def test_candidate_captures_legacy_manager_before_pending_without_stops(self):
        before = (self.config / "transports.json").read_bytes()
        result = self.capture('test "$3" = -capture-upgrade-state || exit 2\necho capture >> "$EVENTS"\nprintf \'{"desired_up":{"vpn":false}}\' > "$4"', stage=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        events = self.events.read_text().splitlines()
        self.assertLess(events.index("capture"), events.index("pending"))
        self.assertNotIn("legacy-cli-called", events)
        self.assertFalse(any(":stop" in event or ":start" in event for event in events))
        self.assertEqual((self.config / "transports.json").read_bytes(), before)
        self.assertEqual(list(self.rescue.glob(".transport-upgrade-capture.*")), [])

    def test_capture_failure_does_not_commit_pending_or_stop_services(self):
        result = self.capture('echo capture >> "$EVENTS"; exit 1', stage=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("before services were stopped", result.stderr)
        events = self.events.read_text()
        self.assertNotIn("pending", events)
        self.assertNotIn(":stop", events)
        self.assertFalse(self.state.exists())
        self.assertEqual(list(self.rescue.glob(".transport-upgrade-capture.*")), [])

    def test_fresh_install_does_not_require_old_manager(self):
        (self.opt / "usr/bin/transport-manager").unlink()
        result = self.capture('exit 99')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.state.exists())

    def test_init_applies_handoff_only_for_upgrade_before_daemon_start(self):
        self.state.write_text("{}")
        self.executable(self.opt / "usr/lib/keen-pbr/rescue-startup-guard.sh", "exit 0")
        (self.init / "rc.func").write_text('printf "%s|%s\\n" "$ARGS" "${PKG_UPGRADE:-unset}"\n')
        source = (FILES / "opt/etc/init.d/S79transport-manager").read_text().replace("/opt/", str(self.opt) + "/")
        for pending, upgrade in ((False, "0"), (True, "0"), (False, "1")):
            with self.subTest(pending=pending, upgrade=upgrade):
                marker = self.rescue / "pending"
                marker.unlink(missing_ok=True)
                if pending:
                    marker.write_text("candidate-staged\n")
                result = self.run_shell(source, "start", PKG_UPGRADE=upgrade)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual("-upgrade-state" in result.stdout, pending or upgrade == "1")
                self.assertTrue(result.stdout.rstrip().endswith("|unset"))

    def test_direct_opkg_capture_precedes_stops_and_failure_keeps_services(self):
        source = (FILES / "prerm").read_text().replace("/opt/", str(self.opt) + "/")
        lock = self.opt / "usr/lib/keen-pbr/lifecycle-lock.sh"
        lock.parent.mkdir(parents=True, exist_ok=True)
        lock.write_text('enter_lifecycle_lock() { echo lock >> "$EVENTS"; }\nrelease_lifecycle_lock() { echo unlock >> "$EVENTS"; }\n')
        for failure in (False, True):
            with self.subTest(failure=failure):
                self.events.unlink(missing_ok=True)
                self.executable(self.opt / "usr/bin/transport-manager", 'echo capture >> "$EVENTS"\n' + ("exit 1" if failure else 'printf \'{}\' > "$4"'))
                result = self.run_shell(source, PKG_UPGRADE="1")
                events = self.events.read_text().splitlines()
                self.assertLess(events.index("lock"), events.index("capture"))
                self.assertEqual(events[-1], "unlock")
                if failure:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(any(":stop" in event for event in events))
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertLess(events.index("capture"), events.index("daemon:stop-for-upgrade"))

    def test_explicit_rollback_drops_inert_direct_upgrade_handoff(self):
        self.state.write_text("stale direct-upgrade intent")
        source = function(RESCUE.read_text(), "rollback_previous")
        source += f"\nTRANSPORT_UPGRADE_STATE='{self.state}'\n"
        source += """
can_rollback_previous() { return 0; }
replace_file_from() { test ! -e "$TRANSPORT_UPGRADE_STATE" || exit 99; return 71; }
rollback_previous
"""
        result = self.run_shell(source)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertFalse(self.state.exists())

    def test_direct_upgrade_with_absent_or_stopped_manager_keeps_existing_lifecycle(self):
        source = (FILES / "prerm").read_text().replace("/opt/", str(self.opt) + "/")
        for absent in (True, False):
            with self.subTest(absent=absent):
                self.events.unlink(missing_ok=True)
                self.state.write_text("stale handoff")
                if absent:
                    (self.opt / "usr/bin/transport-manager").unlink()
                else:
                    self.executable(self.opt / "usr/bin/transport-manager", "exit 99")
                    self.executable(self.init / "S79transport-manager", 'test "$1" != check')
                result = self.run_shell(source, PKG_UPGRADE="1")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("daemon:stop-for-upgrade", self.events.read_text())
                self.assertFalse(self.state.exists())

    def test_rescue_cleanup_removes_handoff(self):
        source = function(RESCUE.read_text(), "cleanup_pending_artifacts")
        source += f"\nROOT='{self.root}'\nTRANSPORT_UPGRADE_STATE='{self.state}'\n"
        for name in ("CANDIDATE_IPK", "PENDING_BASELINE_IPK", "PENDING_TARGET_IPK", "PRE_UPDATE_CONFIG", "PENDING_BASELINE_CONFIG", "PENDING_TARGET_CONFIG"):
            source += f"{name}='{self.rescue / name.lower()}'\n"
        self.state.write_text("{}")
        result = self.run_shell(source + "cleanup_pending_artifacts\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.state.exists())


if __name__ == "__main__":
    unittest.main()

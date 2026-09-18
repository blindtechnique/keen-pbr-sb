"""BusyBox update tests: real IPK metadata/helpers, isolated disk and opkg.

The df fixture accounts for unique IPK inodes, so copying instead of linking
reproduces the Giga's failure. No host /opt, router or network is used.
"""

import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
LIB = ROOT / "packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr"
BUSYBOX = shutil.which("busybox")
RESCUE_SOURCE = (LIB / "rescue-update.sh").read_text().split("\ncommand=${1:-}", 1)[0]
BOUNDARIES = '''
# Ubuntu BusyBox enables standalone applets, which otherwise bypass PATH.
df() { "$SPACE_MOCK_BIN/df" "$@"; }
ln() { if [ -x "$SPACE_MOCK_BIN/ln" ]; then "$SPACE_MOCK_BIN/ln" "$@"; else /bin/ln "$@"; fi; }
'''


def function(source, name):
    start = source.index(name + "() {\n")
    return source[start:source.index("\n}\n", start) + 3]


def package(path, version, size=7651766, installed=18309120):
    control = io.BytesIO()
    content = f"Package: keen-pbr\nVersion: {version}\nInstalled-Size: {installed}\n".encode()
    with tarfile.open(fileobj=control, mode="w:gz") as archive:
        entry = tarfile.TarInfo("./control")
        entry.size = len(content)
        archive.addfile(entry, io.BytesIO(content))
    data = io.BytesIO()
    content = b'#!/bin/sh\necho "capture:$0" >> "$EVENTS"\nprintf \'{}\' > "$4"\n'
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        entry = tarfile.TarInfo("./opt/usr/bin/transport-manager")
        entry.mode = 0o755
        entry.size = len(content)
        archive.addfile(entry, io.BytesIO(content))
    with tarfile.open(path, mode="w:gz") as archive:
        for name, stream in (("control", control), ("data", data)):
            entry = tarfile.TarInfo(f"./{name}.tar.gz")
            entry.size = len(stream.getvalue())
            archive.addfile(entry, io.BytesIO(stream.getvalue()))
    # Trailing zero padding is accepted by gzip/tar and lets fixtures have the
    # exact published archive size without committing megabytes of test data.
    with path.open("ab") as output:
        output.truncate(size)
    return path


@unittest.skipUnless(BUSYBOX, "BusyBox is required")
class UpdateSpaceTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="kpbr-space-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.rescue = self.root / "opt/var/lib/keen-pbr/rescue"
        self.config = self.root / "opt/etc/keen-pbr"
        self.work = self.root / "tmp"
        self.bin = self.root / "mocks"
        for directory in (self.rescue, self.config, self.work, self.bin,
                          self.root / "opt/bin", self.root / "proc"):
            directory.mkdir(parents=True)
        self.events = self.root / "events"
        self.rescue.chmod(0o700)
        self.report = self.root / "space-report"
        self.current = package(self.rescue / "current.ipk", "3.3.2-20260918064958")
        self.previous = package(self.rescue / "previous.ipk", "3.3.2-20260918003245", 7646345)
        self.candidate = package(self.work / "update.ipk", "3.3.2-20260918093748", 7656200)
        for path in (self.current, self.previous):
            Path(str(path) + ".sha256").write_text(hashlib.sha256(path.read_bytes()).hexdigest() + "\n")
        self.current_hash = hashlib.sha256(self.current.read_bytes()).hexdigest()
        (self.config / "config.json").write_text('{"api":{"enabled":false},"user":"unchanged"}\n')
        (self.root / "proc/meminfo").write_text("MemAvailable: 262144 kB\n")
        shutil.copy(LIB / "portable-stat.sh", self.rescue / "portable-stat.sh")
        self.env = {
            **os.environ, "PATH": str(self.bin) + ":" + os.environ["PATH"],
            "KEEN_PBR_RESCUE_ROOT": str(self.root), "TMPDIR": str(self.work),
            "EVENTS": str(self.events), "SPACE_ROOT": str(self.root),
            "SPACE_MOCK_BIN": str(self.bin), "KEEN_PBR_INSTALL_LANGUAGE": "en",
            "KEEN_PBR_UPDATE_SPACE_REPORT": str(self.report),
            "SPACE_OPT_FREE": "21352", "SPACE_TMP_FREE": "248236",
            "SPACE_ORIGINAL_ARCHIVES": str(self.current.stat().st_size + self.previous.stat().st_size),
        }
        self.executable(self.bin / "df", f"""#!{sys.executable}
import os, pathlib, sys
r=pathlib.Path(os.environ['SPACE_ROOT'])
if os.environ.get('SPACE_DF_FAIL') == '1': sys.exit(1)
target=pathlib.Path(sys.argv[-1])
opt=str(target).startswith(str(r/'opt')) or os.environ.get('SPACE_SAME_FS') == '1'
available=int(os.environ['SPACE_OPT_FREE' if opt else 'SPACE_TMP_FREE'])
if opt:
    seen=set(); used=0
    for p in (r/'opt/var/lib/keen-pbr/rescue').glob('*.ipk*'):
        if p.name.endswith('.sha256') or not p.is_file(): continue
        s=p.stat()
        if s.st_ino not in seen: used+=s.st_size; seen.add(s.st_ino)
    available-=(used-int(os.environ['SPACE_ORIGINAL_ARCHIVES'])+1023)//1024
    if os.environ.get('SPACE_RACE') == '1' and (r/'opt/var/lib/keen-pbr/rescue/pending').exists(): available=1000
print('Filesystem 1024-blocks Used Available Capacity Mounted on')
print(('mock-opt' if opt else 'tmpfs')+' 500000 100000 '+str(max(0,available))+' 20% '+str(target))
""", shebang=False)
        self.executable(self.root / "opt/bin/opkg", '''
case "$1" in
 status) printf 'Package: keen-pbr\nVersion: %s\nStatus: install user installed\n' "${SPACE_INSTALLED_VERSION:-3.3.2-20260918064958}" ;;
 *) echo "opkg:$*" >> "$EVENTS" ;;
esac
''')
        result = self.run_rescue('snapshot_config "$PREVIOUS_CONFIG"')
        self.assertEqual(result.returncode, 0, result.stderr)

    def executable(self, path, body, shebang=True):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(("#!/bin/sh\n" if shebang else "") + body + "\n")
        path.chmod(0o755)

    def run_rescue(self, body, **environment):
        return subprocess.run([BUSYBOX, "sh", "-c", RESCUE_SOURCE + BOUNDARIES + "\n" + body],
                              env={**self.env, **environment}, capture_output=True, text=True, timeout=45)

    def stage(self, **environment):
        return self.run_rescue('stage_checked_candidate "$TMPDIR/update.ipk"', **environment)

    def assert_unchanged(self, previous=True):
        self.assertEqual(hashlib.sha256(self.current.read_bytes()).hexdigest(), self.current_hash)
        self.assertIn('"unchanged"', (self.config / "config.json").read_text())
        if previous:
            self.assertTrue(self.previous.exists())
        self.assertFalse(self.events.exists() and "opkg:" in self.events.read_text())

    def test_giga_208_mib_stages_and_promotes_with_one_copy_per_version(self):
        result = self.stage()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Older rollback archive retired", result.stderr)
        self.assertFalse(self.previous.exists())
        self.assertEqual(self.current.stat().st_ino, (self.rescue / "pending-baseline.ipk").stat().st_ino)
        self.assertNotEqual(self.candidate.stat().st_ino, (self.rescue / "candidate.ipk").stat().st_ino)
        self.assert_unchanged(previous=False)
        result = self.run_rescue("promote_candidate")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(hashlib.sha256(self.previous.read_bytes()).hexdigest(), self.current_hash)
        self.assertEqual(self.current.read_bytes(), self.candidate.read_bytes())
        self.assertFalse((self.rescue / "pending").exists())
        self.assertEqual(sorted(p.name for p in self.rescue.glob("*.ipk")), ["current.ipk", "previous.ipk"])

    def test_insufficient_storage_never_stages_or_stops_or_discards_good_copies(self):
        result = self.stage(SPACE_OPT_FREE="8192")
        self.assertEqual(result.returncode, 28, result.stderr)
        self.assertIn("8192", result.stderr)
        self.assertTrue(self.report.read_text().startswith("storage "))
        self.assertFalse((self.rescue / "pending").exists())
        self.assertFalse((self.rescue / "candidate.ipk").exists())
        self.assert_unchanged()

    def test_low_temporary_space_and_low_ram_are_distinguished(self):
        for extra, kind in (({"SPACE_TMP_FREE": "512"}, "temporary"), ({}, "memory")):
            with self.subTest(kind=kind):
                (self.root / "proc/meminfo").write_text("MemAvailable: 8192 kB\n")
                result = self.stage(**extra)
                self.assertEqual(result.returncode, 28, result.stderr)
                self.assertTrue(self.report.read_text().startswith(kind + " "))
                self.assert_unchanged()

    def test_unknown_current_version_does_not_discard_previous_slot(self):
        result = self.stage(SPACE_INSTALLED_VERSION="other-version")
        self.assertEqual(result.returncode, 28, result.stderr)
        self.assert_unchanged()

    def test_failed_config_snapshot_keeps_older_rollback_copy(self):
        config = self.config / "config.json"
        config.rename(self.root / "external-config")
        config.symlink_to(self.root / "external-config")
        result = self.stage()
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assert_unchanged()

    def test_repeated_hardlink_rotation_repairs_sidecar_without_copying_data(self):
        baseline = self.rescue / "pending-baseline.ipk"
        result = self.run_rescue('replace_file_from "$CURRENT_IPK" "$PENDING_BASELINE_IPK"')
        self.assertEqual(result.returncode, 0, result.stderr)
        Path(str(self.current) + ".sha256").write_text("interrupted rename\n")
        result = self.run_rescue('replace_file_from "$PENDING_BASELINE_IPK" "$CURRENT_IPK"; valid_ipk_file "$CURRENT_IPK"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(baseline.stat().st_ino, self.current.stat().st_ino)
        self.assertEqual(list(self.rescue.glob("*.tmp.*")), [])

    def test_old_signed_helper_uses_legacy_preflight_not_an_unknown_command(self):
        helper = self.rescue / "rescue-update.sh"
        self.executable(helper, '''
case "$1" in
 space-protocol) exit 2;;
 stage|promote) echo "legacy:$1" >> "$EVENTS";;
 *) exit 99;;
esac
''')
        source = (ROOT / "install.sh").read_text()
        functions = "\n".join(function(source, name) for name in ("legacy_update_space_check", "install_package_transactionally"))
        functions = functions.replace("/opt/bin/opkg", str(self.root / "opt/bin/opkg"))
        functions = functions.replace("du -sk /opt/etc/keen-pbr", "du -sk " + str(self.config))
        functions = functions.replace("df -Pk /opt", "df -Pk " + str(self.root / "opt"))
        script = f'''
RESCUE_HELPER='{helper}'
PACKAGE_FILE='{self.candidate}'
TMP_DIR='{self.work}'
UPDATE_ONLY=1
say() {{ echo "$1"; }}
die() {{ echo "$1" >&2; exit 1; }}
verify_installed_runtime() {{ return 0; }}
{functions}
install_package_transactionally
'''
        result = self.run_rescue(script, SPACE_OPT_FREE="8192")
        self.assertEqual(result.returncode, 28, result.stderr)
        self.assert_unchanged()
        result = self.run_rescue(script, SPACE_OPT_FREE="100000")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("legacy:stage", self.events.read_text())
        self.assertIn("legacy:promote", self.events.read_text())
        self.assertIn("--tmp-dir " + str(self.work), self.events.read_text())

    def test_linkless_filesystem_is_budgeted_then_uses_copy_fallback(self):
        self.executable(self.bin / "ln", "exit 1")
        result = self.stage()
        self.assertEqual(result.returncode, 28, result.stderr)
        self.assert_unchanged()
        result = self.stage(SPACE_OPT_FREE="100000")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotEqual(self.current.stat().st_ino, (self.rescue / "pending-baseline.ipk").stat().st_ino)
        result = self.run_rescue("promote_candidate", SPACE_OPT_FREE="100000")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_same_filesystem_temporary_files_are_in_storage_budget(self):
        result = self.stage(SPACE_SAME_FS="1")
        self.assertEqual(result.returncode, 28, result.stderr)
        self.assert_unchanged()

    def test_lost_free_space_after_staging_cancels_only_unstarted_attempt(self):
        result = self.stage(SPACE_OPT_FREE="100000", SPACE_RACE="1")
        self.assertEqual(result.returncode, 28, result.stderr)
        self.assertFalse((self.rescue / "pending").exists())
        self.assertFalse((self.rescue / "candidate.ipk").exists())
        self.assertFalse((self.rescue / "pending-baseline.ipk").exists())
        self.assert_unchanged()

    def test_unreadable_capacity_or_invalid_ipk_size_cannot_start_update(self):
        result = self.stage(SPACE_DF_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assert_unchanged()
        package(self.candidate, "new", installed="invalid")
        result = self.stage()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assert_unchanged()

    def test_capture_binary_is_unpacked_to_tmp_and_removed_after_use(self):
        self.executable(self.root / "opt/usr/bin/transport-manager", "exit 99")
        self.executable(self.root / "opt/etc/init.d/S79transport-manager", 'echo "transport:$1" >> "$EVENTS"; test "$1" = check')
        (self.config / "transports.json").write_text("{}\n")
        result = self.stage()
        self.assertEqual(result.returncode, 0, result.stderr)
        events = self.events.read_text()
        self.assertIn("capture:" + str(self.work) + "/kpbr-transport-upgrade.", events)
        self.assertNotIn(":stop", events)
        self.assertEqual(list(self.work.glob("kpbr-transport-upgrade.*")), [])
        self.assertEqual(list(self.rescue.glob(".transport-upgrade*")), [])

    def test_external_download_changes_do_not_modify_staged_recovery_archive(self):
        result = self.stage(SPACE_OPT_FREE="100000")
        self.assertEqual(result.returncode, 0, result.stderr)
        candidate_hash = hashlib.sha256((self.rescue / "candidate.ipk").read_bytes()).hexdigest()
        self.candidate.write_text("external download overwritten")
        self.assertEqual(hashlib.sha256((self.rescue / "candidate.ipk").read_bytes()).hexdigest(), candidate_hash)

    def test_existing_pending_transaction_is_not_cleared_by_space_check(self):
        pending = self.rescue / "pending"
        pending.write_text("candidate-staged\n")
        result = self.stage()
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertTrue(pending.exists())
        self.assert_unchanged()

    def test_installer_does_not_invoke_opkg_when_shared_preflight_fails(self):
        helper = self.rescue / "rescue-update.sh"
        self.executable(helper, RESCUE_SOURCE + BOUNDARIES + '\ncase "$1" in space-protocol) echo 1;; stage-checked) stage_checked_candidate "$2";; *) exit 99;; esac')
        source = function((ROOT / "install.sh").read_text(), "install_package_transactionally")
        source = source.replace("/opt/bin/opkg", str(self.root / "opt/bin/opkg"))
        body = f'''
RESCUE_HELPER='{helper}'
PACKAGE_FILE='{self.candidate}'
say() {{ echo "$1"; }}
die() {{ echo "$1" >&2; exit 1; }}
{source}
install_package_transactionally
'''
        result = self.run_rescue(body, SPACE_OPT_FREE="8192")
        self.assertEqual(result.returncode, 28, result.stderr)
        self.assert_unchanged()

    def test_web_cleanup_keeps_capacity_explanation_and_returns_failure(self):
        source = (LIB / "self-update.sh").read_text()
        functions = "\n".join(function(source, name) for name in ("space_failure_message", "write_state", "cleanup"))
        state = self.root / "state.json"
        work = self.root / "keen-pbr-sb-update.test"
        work.mkdir()
        (work / "space-report").write_text("storage 27000 8192\n")
        script = f'''set -u
{functions}
WORK_DIR='{work}'
STATE_FILE='{state}'
RUN_FILE_OWNED=0
LOCK_TOKEN=
finished=0
trap cleanup EXIT
exit 28
'''
        result = subprocess.run([BUSYBOX, "sh", "-c", script], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 28, result.stderr)
        value = json.loads(state.read_text())
        self.assertEqual(value["phase"], "failed")
        self.assertFalse(value["running"])
        self.assertIn("27000", value["message"])
        self.assertIn("8192", value["message"])
        self.assertIn("не изменена", value["message"])
        self.assert_unchanged()

    def test_removed_init_scripts_do_not_block_baseline_reinstallation(self):
        result = self.run_rescue("stop_runtime")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_init_does_not_hide_a_live_daemon_or_elf_loader(self):
        proc = self.root / "proc/1234"
        proc.mkdir()
        for argv in (("/opt/usr/bin/keen-pbr", "-config", "config.json"),
                     ("/opt/lib/ld-2.27.so", "--library-path", "/opt/lib", "/opt/usr/bin/transport-manager")):
            with self.subTest(argv=argv):
                (proc / "cmdline").write_bytes(b"\0".join(s.encode() for s in argv) + b"\0")
                result = self.run_rescue("stop_runtime")
                self.assertEqual(result.returncode, 1, result.stderr)
        (proc / "cmdline").write_bytes(b"/bin/cat\0/opt/usr/bin/keen-pbr\0")
        result = self.run_rescue("stop_runtime")
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()

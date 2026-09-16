"""First-install ordering/retry tests; real BusyBox, optional real DNS sockets.

No router access or package build. Tests execute install.sh's function bodies;
fixed /opt paths, opkg, NDMS and runtime checks are isolated fixture boundaries.
With dnsmasq installed, a separate test binds real TCP/UDP port 53 and tests
the shipped standalone -> managed configuration handoff (container only).
"""

from pathlib import Path
import io
import http.server
import os
import re
import shutil
import socket
import struct
import subprocess
import tarfile
import tempfile
import threading
import time
import unittest


ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path(os.environ.get("KPBR_TEST_INSTALLER", ROOT / "install.sh")).read_text(encoding="utf8")
PACKAGE = ROOT / "packages/keenetic/keen-pbr/files"
BUSYBOX = shutil.which("busybox")
IPK_UNDER_TEST = os.environ.get("KPBR_TEST_IPK")
PACKAGED_FILES = {}
if IPK_UNDER_TEST:
    with tarfile.open(IPK_UNDER_TEST, "r:gz") as outer:
        payload = outer.extractfile("./data.tar.gz").read()
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
        for member in archive:
            if member.isfile() and member.name.endswith((".sh", ".template", "dnsmasq-fallback.conf")):
                PACKAGED_FILES[member.name.removeprefix("./")] = archive.extractfile(member).read()


def packaged_text(part):
    if IPK_UNDER_TEST:
        return PACKAGED_FILES[part].decode()
    return (PACKAGE / part).read_text()


def function(name):
    start = SOURCE.index(name + "() {\n")
    return SOURCE[start:SOURCE.index("\n}\n", start) + 3]


@unittest.skipUnless(BUSYBOX, "BusyBox required")
class InstallerFirstRunTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="kpbr-first-install-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.opt = self.root / "opt"
        self.work = self.root / "mykeenpbr-install.test"
        self.work.mkdir()
        for part in ("bin", "sbin", "etc/init.d", "etc/keen-pbr", "usr/lib/keen-pbr", "var/lib/keen-pbr/rescue"):
            (self.opt / part).mkdir(parents=True)
        self.rescue = self.opt / "var/lib/keen-pbr/rescue"
        self.effects = self.root / "effects"
        self.status = self.root / "package-status"
        self.status.write_text("unpacked\n")
        self.override = self.root / "override"
        self.override.write_text("N\n")
        self.running = self.root / "dns-running"
        self.running.write_text("N\n")
        self.config = self.opt / "etc/dnsmasq.conf"
        self.config.write_text("# operator original\nserver=192.0.2.53\n")
        self.config.chmod(0o640)
        self.original = self.config.read_bytes()
        self.ipk = self.root / "verified.ipk"
        self.ipk.write_bytes(b"same-authenticated-package-fixture\n")
        self.make_payload()
        self.executable(self.opt / "sbin/dnsmasq", 'exit 0')
        self.executable(self.opt / "etc/init.d/S80keen-pbr", f'echo "core $1" >> "{self.effects}"')
        self.executable(self.opt / "etc/init.d/S56dnsmasq", f'''
echo "dns $1" >> '{self.effects}'
case "$1" in
    stop) echo N > '{self.running}';;
    start|restart)
        [ "$(cat '{self.override}')" = Y ] || {{ echo 'port 53 is occupied' >&2; exit 1; }}
        [ "${{TEST_DNS_FAIL:-0}}" != 1 ] || exit 1
        echo Y > '{self.running}';;
esac
''')
        self.executable(self.opt / "bin/opkg", f'''
case "$1" in
    status)
        [ "$2" = keen-pbr ] || exit 0
        echo "Status: install user $(cat '{self.status}')"
        exit 0;;
    --force-reinstall)
        echo "opkg install cap=${{KEEN_PBR_PACKAGE_UNKNOWN_RECOVERY:-}}" >> '{self.effects}'
        [ "$(cat '{self.running}')" = Y ] || exit 17
        if [ -e '{self.rescue}/UNKNOWN' ]; then
            [ "${{KEEN_PBR_PACKAGE_UNKNOWN_RECOVERY:-}}" = recover-pending-v1 ] || exit 18
        fi
        [ "${{TEST_PACKAGE_FAIL:-0}}" != 1 ] || exit 19
        echo installed > '{self.status}'
        ;;
    install) echo "dependency $2" >> '{self.effects}'; exit 23;;
    *) echo "opkg $*" >> '{self.effects}';;
esac
''')
        self.executable(self.rescue / "rescue-update.sh", f'''
echo "rescue $1" >> '{self.effects}'
case "$1" in
    stage)
        [ ! -e '{self.rescue}/pending' ] && [ ! -e '{self.rescue}/UNKNOWN' ] || exit 8
        cp "$2" '{self.rescue}/candidate.ipk'
        echo candidate-staged > '{self.rescue}/pending';;
    verify) [ "${{TEST_VERIFY_FAIL:-0}}" != 1 ] || exit 9;;
    promote)
        cp '{self.rescue}/candidate.ipk' '{self.rescue}/current.ipk'
        rm '{self.rescue}/pending';;
    rollback-candidate) echo 'must not try no-baseline rollback' >&2; exit 91;;
esac
''')

    def executable(self, path, body):
        path.write_text("#!/bin/sh\nset -eu\n" + body + "\n")
        path.chmod(0o755)

    def map_paths(self, text):
        # Archive member names './opt/...' are not filesystem paths.
        return re.sub(r"(?<!\.)/opt/", str(self.opt) + "/", text)

    def make_payload(self):
        with tarfile.open(self.work / "data.tar.gz", "w:gz") as archive:
            for part in ("opt/usr/lib/keen-pbr/dnsmasq.conf.template", "opt/etc/keen-pbr/dnsmasq-fallback.conf"):
                data = self.map_paths(packaged_text(part)).encode()
                member = tarfile.TarInfo("./" + part)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))

    def run_shell(self, tail, overrides="", cleanup=False):
        names = ("cleanup", "read_dns_override_state", "restore_dns_setup", "configure_dns",
                 "ask_dns_setup", "choose_optional_setup", "prepare_first_install_dns", "prepare_first_install_retry",
                 "verify_installed_runtime", "install_package_transactionally", "remember_initial_nfqws_config", "configure_nfqws2")
        definitions = self.map_paths("\n".join(function(name) for name in names))
        script = f'''set -eu
TMP_DIR='{self.work}'
RESCUE_DIR='{self.rescue}'
RESCUE_HELPER="$RESCUE_DIR/rescue-update.sh"
PACKAGE_FILE='{self.ipk}'
DNS_SETUP_CHOICE=Y
NFQWS_SETUP_CHOICE=N
DNS_BOOTSTRAP=0
DNS_INSTALL_ROLLBACK=0
FIRST_PACKAGE_STARTED=0
RESUME_FIRST_INSTALL=0
FALLBACK_CLEANUP_OWNED=0
LOCK_OWNED=0
UPDATE_ONLY=0
say() {{ printf '%s\\n' "$*"; }}
die() {{ say "$*" >&2; exit 1; }}
ask() {{ echo "ask $1" >> '{self.effects}'; printf '%s\\n' "$2"; }}
pidof() {{ [ "$(cat '{self.running}')" = Y ]; }}
nslookup() {{ return 0; }}
run_ndmc() {{
    echo "ndmc $1" >> '{self.effects}'
    case "$1" in
        'show running-config')
            ndmc_output='! fixture'
            [ "$(cat '{self.override}')" != Y ] || ndmc_output='opkg dns-override';;
        'opkg dns-override') echo Y > '{self.override}';;
        'no opkg dns-override') echo N > '{self.override}';;
    esac
    return 0
}}
{definitions}
{overrides}
{"trap cleanup EXIT; trap 'exit 129' HUP" if cleanup else ""}
{tail}
'''
        return subprocess.run([BUSYBOX, "sh", "-c", script], capture_output=True, text=True, timeout=20)

    def test_initial_nfqws_default_is_copied_without_changing_active_config(self):
        active = self.opt / "etc/nfqws2/nfqws2.conf"
        active.parent.mkdir()
        content = b'ISP_INTERFACE="eth3"\nIPV6_ENABLED=0\nNFQWS_ARGS="vendor defaults"\n'
        active.write_bytes(content)
        result = self.run_shell("remember_initial_nfqws_config; remember_initial_nfqws_config")
        self.assertEqual(result.returncode, 0, result.stderr)
        copies = list((self.opt / "etc/keen-pbr/nfqws-strategies").glob("default (*).conf"))
        self.assertEqual(len(copies), 1)
        self.assertEqual(copies[0].read_bytes(), content)
        self.assertEqual(active.read_bytes(), content)
        self.assertFalse(self.effects.exists())  # No restart, opkg or NDMS calls.

    def test_clean_nfqws_install_registers_the_actual_postinst_config(self):
        active = self.opt / "etc/nfqws2/nfqws2.conf"
        active.parent.mkdir()
        self.executable(self.opt / "bin/opkg", f'''
case "$*" in
  'status nfqws2-keenetic') exit 0;;
  'install nfqws2-keenetic') printf '%s\\n' 'ISP_INTERFACE="eth3"' 'NFQWS_ARGS="vendor"' > '{active}';;
esac
''')
        result = self.run_shell("NFQWS_SETUP_CHOICE=Y; configure_nfqws2")
        self.assertEqual(result.returncode, 0, result.stderr)
        copies = list((self.opt / "etc/keen-pbr/nfqws-strategies").glob("*.conf"))
        self.assertEqual(len(copies), 1)
        self.assertEqual(copies[0].read_bytes(), active.read_bytes())

    def test_existing_nfqws_config_is_never_relabeled_as_a_vendor_default(self):
        active = self.opt / "etc/nfqws2/nfqws2.conf"
        active.parent.mkdir()
        original = b'NFQWS_ARGS="operator changes"\n'
        active.write_bytes(original)
        self.executable(self.opt / "bin/opkg", '''
case "$*" in
  'status nfqws2-keenetic') echo 'Status: install user installed';;
esac
''')
        result = self.run_shell("NFQWS_SETUP_CHOICE=Y; configure_nfqws2")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(active.read_bytes(), original)
        self.assertFalse((self.opt / "etc/keen-pbr/nfqws-strategies").exists())

    def test_nfqws_default_capture_does_not_overwrite_an_earlier_strategy(self):
        active = self.opt / "etc/nfqws2/nfqws2.conf"
        active.parent.mkdir()
        active.write_text('NFQWS_ARGS="first vendor version"\n')
        self.assertEqual(self.run_shell("remember_initial_nfqws_config").returncode, 0)
        active.write_text('NFQWS_ARGS="second vendor version"\n')
        result = self.run_shell("remember_initial_nfqws_config")
        self.assertEqual(result.returncode, 0, result.stderr)
        copies = list((self.opt / "etc/keen-pbr/nfqws-strategies").glob("*.conf"))
        self.assertEqual(len(copies), 2)
        self.assertEqual({p.read_text() for p in copies}, {
            'NFQWS_ARGS="first vendor version"\n', 'NFQWS_ARGS="second vendor version"\n'})

    def pending_first(self, unknown=True):
        (self.rescue / "candidate.ipk").write_bytes(self.ipk.read_bytes())
        (self.rescue / "pending").write_text("candidate-staged\n")
        if unknown:
            (self.rescue / "UNKNOWN").write_text("candidate rollback has no verified baseline\n")

    def effects_text(self):
        return self.effects.read_text() if self.effects.exists() else ""

    def test_fresh_dns_precedes_package_and_survives_success(self):
        result = self.run_shell("prepare_first_install_retry\nchoose_optional_setup\nprepare_first_install_dns\ninstall_package_transactionally", cleanup=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        events = self.effects_text()
        self.assertLess(events.index("ask Установить nfqws2"), events.index("dns restart"))
        self.assertLess(events.index("dns restart"), events.index("opkg install"))
        self.assertNotIn("rollback-candidate", events)
        self.assertIn("# BEGIN keen-pbr standalone DNS fallback v1", self.config.read_text())
        self.assertNotIn("conf-script=", self.config.read_text())
        self.assertEqual(self.override.read_text().strip(), "Y")
        self.assertEqual(self.running.read_text().strip(), "Y")

    def test_clean_entware_installs_dns_dependency_before_override(self):
        # No dnsmasq binary or init script exists yet, as on freshly wiped
        # Entware. Its dependency has no postinst; configuration comes next.
        binary = self.opt / "sbin/dnsmasq"
        service = self.opt / "etc/init.d/S56dnsmasq"
        binary.rename(self.root / "dnsmasq-package-binary")
        service.rename(self.root / "dnsmasq-package-service")
        opkg = self.opt / "bin/opkg"
        opkg.write_text(opkg.read_text().replace('case "$1" in', f'''
if [ "$1" = install ] && [ "$2" = dnsmasq ]; then
    echo 'dependency dnsmasq' >> '{self.effects}'
    cp '{self.root}/dnsmasq-package-binary' '{binary}'
    cp '{self.root}/dnsmasq-package-service' '{service}'
    exit 0
fi
case "$1" in''', 1))
        self.status.write_text("not-installed\n")
        result = self.run_shell("prepare_first_install_dns\ninstall_package_transactionally", cleanup=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        events = self.effects_text()
        self.assertLess(events.index("dependency dnsmasq"), events.index("ndmc opkg dns-override"))
        self.assertLess(events.index("dns restart"), events.index("opkg install"))
        self.assertEqual(self.override.read_text().strip(), "Y")
        self.assertTrue(binary.exists())

    def test_retry_previous_unpacked_first_install(self):
        self.pending_first()
        result = self.run_shell("prepare_first_install_retry\nprepare_first_install_dns\ninstall_package_transactionally", cleanup=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("rescue stage", self.effects_text())
        self.assertIn("cap=recover-pending-v1", self.effects_text())
        self.assertFalse((self.rescue / "UNKNOWN").exists())
        self.assertFalse((self.rescue / "pending").exists())
        self.assertEqual((self.rescue / "current.ipk").read_bytes(), self.ipk.read_bytes())

    def test_retry_pending_without_unknown(self):
        self.pending_first(unknown=False)
        result = self.run_shell("prepare_first_install_retry\nprepare_first_install_dns\ninstall_package_transactionally")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_retry_after_successful_opkg_and_failed_readiness_restores_dns_first(self):
        # Giga 2026-09-16: postinst completed, then the 30-second API probe
        # expired. cleanup restored native DNS but opkg correctly says installed.
        self.status.write_text("installed\n")
        self.pending_first(unknown=False)
        result = self.run_shell("prepare_first_install_retry\nprepare_first_install_dns\ninstall_package_transactionally", cleanup=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        events = self.effects_text()
        self.assertLess(events.index("dns restart"), events.index("opkg install"))
        self.assertNotIn("core stop", events)
        self.assertEqual(self.override.read_text().strip(), "Y")

    def make_slow_verifier(self, failed_windows):
        helper = self.rescue / "rescue-update.sh"
        helper.write_text(helper.read_text().replace(
            'verify) [ "${TEST_VERIFY_FAIL:-0}" != 1 ] || exit 9;;',
            f'''verify)
        count=0
        [ ! -f '{self.root}/verify-count' ] || count=$(cat '{self.root}/verify-count')
        count=$((count + 1))
        echo "$count" > '{self.root}/verify-count'
        [ "$count" -gt {failed_windows} ] || exit 1;;'''))

    def test_first_install_waits_for_cold_boot_without_stopping_services(self):
        self.make_slow_verifier(failed_windows=1)
        result = self.run_shell("prepare_first_install_dns\ninstall_package_transactionally", cleanup=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "verify-count").read_text().strip(), "2")
        self.assertNotIn("core stop", self.effects_text())
        self.assertNotIn("dns stop", self.effects_text())
        self.assertFalse((self.rescue / "pending").exists())

    def test_failed_first_install_wait_is_bounded_and_not_promoted(self):
        self.make_slow_verifier(failed_windows=99)
        result = self.run_shell("prepare_first_install_dns\ninstall_package_transactionally", cleanup=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.root / "verify-count").read_text().strip(), "3")
        self.assertNotIn("rescue promote", self.effects_text())
        self.assert_dns_restored()

    def test_existing_package_keeps_single_verification_window(self):
        self.status.write_text("installed\n")
        self.running.write_text("Y\n")
        self.make_slow_verifier(failed_windows=1)
        result = self.run_shell("install_package_transactionally")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.root / "verify-count").read_text().strip(), "1")

    def test_first_install_with_manual_dns_also_waits_for_cold_boot(self):
        self.running.write_text("Y\n")
        self.make_slow_verifier(failed_windows=1)
        result = self.run_shell("DNS_SETUP_CHOICE=N\nprepare_first_install_dns\ninstall_package_transactionally")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertEqual((self.root / "verify-count").read_text().strip(), "2")

    def test_verifier_lock_error_is_not_retried_as_slow_boot(self):
        helper = self.rescue / "rescue-update.sh"
        helper.write_text(helper.read_text().replace(
            'verify) [ "${TEST_VERIFY_FAIL:-0}" != 1 ] || exit 9;;',
            'verify) exit 75;;'))
        result = self.run_shell("prepare_first_install_dns\ninstall_package_transactionally", cleanup=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.effects_text().count("rescue verify"), 1)
        self.assertNotIn("rescue promote", self.effects_text())

    def test_first_run_continues_to_auth_and_selected_nfqws_after_slow_boot(self):
        self.make_slow_verifier(failed_windows=1)
        opkg = self.opt / "bin/opkg"
        opkg.write_text(opkg.read_text().replace(
            'case "$1" in', f'''
if [ "$1" = install ]; then
    case "$2" in
        ca-certificates|nfqws2-keenetic)
            echo "optional install $2" >> '{self.effects}'
            exit 0;;
    esac
fi
case "$1" in''', 1))
        tail = SOURCE[SOURCE.index('\nif [ "$UPDATE_ONLY" = "1" ]; then\n    say "Устанавливаю обновление'):]
        overrides = f'''
ask() {{ printf '%s\\n' Y; }}
choose_sing_box() {{ :; }}
set_sing_box_path() {{ :; }}
configure_web_auth() {{ echo configure-auth >> '{self.effects}'; }}
'''
        result = self.run_shell(self.map_paths(tail), overrides, cleanup=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        events = self.effects_text()
        self.assertLess(events.index("rescue promote"), events.index("configure-auth"))
        self.assertLess(events.index("configure-auth"), events.index("optional install nfqws2-keenetic"))
        self.assertNotIn("core stop", events)
        self.assertIn("Установка завершена.", result.stdout)

    def assert_dns_restored(self):
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o640)
        self.assertEqual(self.override.read_text().strip(), "N")
        self.assertEqual(self.running.read_text().strip(), "N")

    def test_failed_first_package_restores_dns_and_stays_retryable(self):
        result = self.run_shell("prepare_first_install_dns\ninstall_package_transactionally", "export TEST_PACKAGE_FAIL=1", cleanup=True)
        self.assertNotEqual(result.returncode, 0)
        self.assert_dns_restored()
        self.assertTrue((self.rescue / "pending").exists())
        self.assertFalse((self.rescue / "UNKNOWN").exists())
        self.assertNotIn("rollback-candidate", self.effects_text())

    def test_failed_retry_keeps_original_unknown_and_snapshot(self):
        self.pending_first()
        result = self.run_shell("prepare_first_install_retry\nprepare_first_install_dns\ninstall_package_transactionally", "export TEST_PACKAGE_FAIL=1", cleanup=True)
        self.assertNotEqual(result.returncode, 0)
        self.assert_dns_restored()
        self.assertTrue((self.rescue / "UNKNOWN").exists())
        self.assertTrue((self.rescue / "pending").exists())

    def test_failed_runtime_verification_does_not_clear_unknown(self):
        self.pending_first()
        result = self.run_shell("prepare_first_install_retry\nprepare_first_install_dns\ninstall_package_transactionally", "export TEST_VERIFY_FAIL=1", cleanup=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.rescue / "UNKNOWN").exists())
        self.assert_dns_restored()

    def test_interruption_after_dns_restores_native_dns(self):
        result = self.run_shell("prepare_first_install_dns\nkill -HUP $$", cleanup=True)
        self.assertNotEqual(result.returncode, 0)
        self.assert_dns_restored()

    def test_dns_start_failure_does_not_enter_package_install(self):
        result = self.run_shell("prepare_first_install_dns\ninstall_package_transactionally", "export TEST_DNS_FAIL=1", cleanup=True)
        self.assertNotEqual(result.returncode, 0)
        self.assert_dns_restored()
        self.assertNotIn("opkg install", self.effects_text())

    def test_existing_installed_dns_is_not_replaced_by_bootstrap(self):
        self.status.write_text("installed\n")
        result = self.run_shell("prepare_first_install_dns")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertEqual(self.effects_text(), "")

    def test_declined_dns_stops_before_unpack_without_touching_dns(self):
        result = self.run_shell("DNS_SETUP_CHOICE=N\nprepare_first_install_dns\ninstall_package_transactionally")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertEqual(self.effects_text(), "")

    def test_declined_dns_accepts_existing_manual_resolver(self):
        self.running.write_text("Y\n")
        result = self.run_shell("DNS_SETUP_CHOICE=N\nprepare_first_install_dns")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.config.read_bytes(), self.original)

    def test_declined_nfqws_performs_no_package_operations(self):
        result = self.run_shell("configure_nfqws2")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.effects_text(), "")

    def test_dependency_failure_leaves_native_dns_untouched(self):
        (self.opt / "sbin/dnsmasq").unlink()
        result = self.run_shell("prepare_first_install_dns")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertEqual(self.override.read_text().strip(), "N")
        self.assertNotIn("ndmc", self.effects_text())

    def test_custom_fallback_preserved(self):
        (self.opt / "etc/keen-pbr/dnsmasq-fallback.conf").write_text("server=192.0.2.7#5300\n")
        result = self.run_shell("prepare_first_install_dns")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("server=192.0.2.7#5300", self.config.read_text())
        self.assertNotIn("server=9.9.9.9", self.config.read_text())

    def test_different_pending_package_not_resumed(self):
        self.pending_first()
        (self.rescue / "candidate.ipk").write_bytes(b"different package")
        result = self.run_shell("prepare_first_install_retry")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.rescue / "UNKNOWN").exists())
        self.assertEqual(self.effects_text(), "")

    def test_unrelated_unknown_not_resumed(self):
        self.pending_first()
        (self.rescue / "UNKNOWN").write_text("other fault\n")
        result = self.run_shell("prepare_first_install_retry")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.rescue / "UNKNOWN").read_text(), "other fault\n")

    def test_pending_update_with_baseline_not_treated_as_first_install(self):
        self.pending_first()
        (self.rescue / "pending-baseline.ipk").write_bytes(b"old version")
        result = self.run_shell("prepare_first_install_retry")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.effects_text(), "")

    def test_update_only_does_not_prompt_or_configure_dns(self):
        # Execute the actual entrypoint after download/bootstrap boundaries.
        tail = SOURCE[SOURCE.index('\nif [ "$UPDATE_ONLY" = "1" ]; then\n    say "Устанавливаю обновление'):]
        result = self.run_shell(tail, "UPDATE_ONLY=1\ninstall_package_transactionally() { say update-only; }")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.effects_text(), "")
        self.assertIn("update-only", result.stdout)

    def test_retry_with_actual_published_rescue_and_startup_guard(self):
        # Use the unmodified helpers from the IPK. Only opkg and the service
        # check endpoints are fixtures; journal, snapshots, hashes, lock and
        # the UNKNOWN capability check are the shipped implementations.
        self.rescue.chmod(0o700)
        (self.opt / "var/run").mkdir(parents=True, exist_ok=True)
        (self.opt / "var/log").mkdir(parents=True, exist_ok=True)
        for name in ("rescue-update.sh", "rescue-startup-guard.sh", "portable-stat.sh", "update-lock.sh"):
            destination = self.rescue / name
            destination.write_text(packaged_text("opt/usr/lib/keen-pbr/" + name))
            destination.chmod(0o755)
        self.executable(self.opt / "etc/init.d/S79transport-manager", "exit 0")
        (self.opt / "etc/keen-pbr/config.json").write_text('{"api":{"enabled":false}}\n')
        opkg = self.opt / "bin/opkg"
        opkg.write_text(opkg.read_text().replace(
            'echo installed >',
            f'KEEN_PBR_PACKAGE_POSTINST=1 "{self.rescue}/rescue-startup-guard.sh" start\n        echo installed >'))
        overrides = f'''
export KEEN_PBR_RESCUE_ROOT='{self.root}'
export KEEN_PBR_UPDATE_LOCK_PID=$$
KEEN_PBR_UPDATE_LOCK_TOKEN=$("$RESCUE_DIR/update-lock.sh" acquire $$)
export KEEN_PBR_UPDATE_LOCK_TOKEN
'''
        result = self.run_shell('''
"$RESCUE_HELPER" stage "$PACKAGE_FILE"
printf '%s\n' 'candidate rollback has no verified baseline' > "$RESCUE_DIR/UNKNOWN"
prepare_first_install_retry
prepare_first_install_dns
install_package_transactionally
"$RESCUE_DIR/rescue-startup-guard.sh" start
"$RESCUE_DIR/update-lock.sh" release $$ "$KEEN_PBR_UPDATE_LOCK_TOKEN"
''', overrides)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.rescue / "UNKNOWN").exists())
        self.assertFalse((self.rescue / "pending").exists())
        self.assertTrue((self.rescue / "current.ipk.sha256").exists())
        self.assertEqual((self.rescue / "current.ipk").read_bytes(), self.ipk.read_bytes())

    @unittest.skipUnless(os.environ.get("KPBR_TEST_REAL_DNS") == "1" and
                         Path("/.dockerenv").exists() and shutil.which("dnsmasq"),
                         "real port-53 test is opt-in and container-only")
    def test_real_port_53_and_published_dns_handoff(self):
        dnsmasq = shutil.which("dnsmasq")
        native = []
        process = None
        dns_log = self.root / "dns.log"

        def occupy():
            for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                sock = socket.socket(socket.AF_INET, kind)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("0.0.0.0", 53))
                if kind == socket.SOCK_STREAM:
                    sock.listen()
                native.append(sock)

        def release():
            while native:
                native.pop().close()

        def stop_dns():
            nonlocal process
            if process:
                process.terminate()
                process.wait(timeout=5)
                process = None

        def query():
            labels = b"".join(bytes([len(s)]) + s.encode() for s in "my.keenetic.net".split("."))
            request = struct.pack("!6H", 1234, 0x100, 1, 0, 0, 0) + labels + b"\0\0\1\0\1"
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(0.2)
                client.sendto(request, ("127.0.0.1", 53))
                response, _ = client.recvfrom(2048)
            if not response.endswith(socket.inet_aton("78.47.125.180")):
                raise AssertionError(f"unexpected local DNS response: {response!r}")

        def start_dns():
            nonlocal process
            stop_dns()
            with dns_log.open("ab") as log:
                process = subprocess.Popen([dnsmasq, "--keep-in-foreground", "--user=root",
                                            "--pid-file=" + str(self.root / "dns.pid"),
                                            "--conf-file=" + str(self.config)], stdout=log, stderr=log)
            for _ in range(30):
                if process.poll() is not None:
                    raise AssertionError(dns_log.read_text())
                try:
                    query()
                    return
                except (OSError, AssertionError):
                    time.sleep(0.03)
            raise AssertionError("DNS did not answer after start: " + dns_log.read_text())

        def dispatch(path):
            if path == "/enable":
                release()
                self.override.write_text("Y\n")
            elif path == "/disable":
                occupy()
                self.override.write_text("N\n")
            elif path in ("/dns/start", "/dns/restart"):
                start_dns()
                self.running.write_text("Y\n")
            elif path == "/dns/stop":
                stop_dns()
                self.running.write_text("N\n")
            else:
                raise AssertionError(path)

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                try:
                    dispatch(self.path)
                    self.send_response(200)
                    self.end_headers()
                except Exception as error:
                    self.send_response(500)
                    self.end_headers()
                    self.wfile.write(str(error).encode())

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        client = self.root / "control.py"
        client.write_text("import sys, urllib.request\n"
                          f"urllib.request.urlopen('http://127.0.0.1:{server.server_port}/' + sys.argv[1], timeout=5).read()\n")
        self.executable(self.opt / "sbin/dnsmasq", f'exec "{dnsmasq}" "$@"')
        self.executable(self.opt / "etc/init.d/S56dnsmasq", f'python3 "{client}" "dns/$1"')
        restore = self.root / "dnsmasq-package.sh"
        restore.write_text(packaged_text("opt/usr/lib/keen-pbr/dnsmasq-package.sh").replace(
            "MANAGED_SCRIPT='conf-script=/opt/", "MANAGED_SCRIPT='conf-script=" + str(self.opt) + "/"))
        restore.chmod(0o755)
        fake_conf_script = self.opt / "usr/lib/keen-pbr/dnsmasq.sh"
        # Added only AFTER bootstrap: a clean router has no package conf-script.
        overrides = f'''
run_ndmc() {{
    case "$1" in
        'show running-config') ndmc_output='! fixture'; return 0;;
        'opkg dns-override') python3 '{client}' enable;;
        'no opkg dns-override') python3 '{client}' disable;;
        'system configuration save') return 0;;
    esac
}}
'''
        try:
            occupy()
            old = subprocess.run([dnsmasq, "--keep-in-foreground", "--user=root", "--conf-file=" + str(self.config)],
                                 capture_output=True, text=True, timeout=3)
            self.assertNotEqual(old.returncode, 0, "old ordering must fail while native DNS owns 53")
            self.assertIn("Address in use", old.stderr)
            result = self.run_shell("prepare_first_install_dns", overrides)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("conf-script=", self.config.read_text())
            query()
            self.executable(fake_conf_script, "echo 'server=192.0.2.53'")
            attached = subprocess.run([BUSYBOX, "sh", str(restore), "restore"],
                                      env={**os.environ, "KEEN_PBR_RESCUE_ROOT": str(self.root)},
                                      capture_output=True, text=True, timeout=5)
            self.assertEqual(attached.returncode, 0, attached.stderr)
            self.assertIn("conf-script=" + str(fake_conf_script), self.config.read_text())
            self.assertNotIn("# BEGIN keen-pbr standalone DNS fallback v1", self.config.read_text())
            start_dns()
            query()
        finally:
            stop_dns()
            release()
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()

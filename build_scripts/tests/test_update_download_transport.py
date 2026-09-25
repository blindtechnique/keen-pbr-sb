"""Offline update-download wiring: no real /opt, network, opkg or services."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
BUSYBOX = os.environ.get("BUSYBOX") or shutil.which("busybox")


@unittest.skipUnless(BUSYBOX, "BusyBox sh required")
class UpdateDownloadTransportTest(unittest.TestCase):
    def run_fetch(self, source, function, override, preference=False, failure=False, missing_binary=False):
        text = source.read_text(encoding="utf8")
        function_text = function + "() {" + text.split(function + "() {", 1)[1].split("\n}", 1)[0] + "\n}\n"
        with tempfile.TemporaryDirectory(prefix="kpbr-update-transport-") as temporary:
            work = Path(temporary)
            pref = work / "preference"
            if preference:
                if preference == "symlink":
                    pref.symlink_to(work / "missing-preference")
                else:
                    pref.write_text("group\n")
            binary = work / "keen-pbr"
            binary.write_text('#!/bin/sh\nprintf "bound:%s:%s:%s:%s\\n" "$1" "$2" "$3" "${KEEN_PBR_UPDATE_OUTBOUND-unset}"\nexit ' + ("17" if failure else "0") + "\n")
            binary.chmod(0o700)
            if missing_binary:
                binary.unlink()
            function_text = function_text.replace("/opt/usr/bin/keen-pbr", str(binary)).replace("/opt/etc/keen-pbr/update-outbound", str(pref))
            function_text = function_text.replace("/opt/bin/curl", "curl").replace("/opt/bin/wget", "wget")
            # Disable absolute-executable probes; the fallback uses the mock curl.
            function_text = function_text.replace('[ -x curl ]', 'false').replace('[ -x wget ]', 'false')
            script = 'curl() { echo unbound; }; wget() { echo unbound; }; die() { exit 19; };\n' + function_text
            if function == "fetch":
                initialization = text.split("UPDATE_DOWNLOAD_OVERRIDE_PRESENT=", 1)[1].split("unset KEEN_PBR_UPDATE_OUTBOUND", 1)[0]
                script = "UPDATE_DOWNLOAD_OVERRIDE_PRESENT=" + initialization + "unset KEEN_PBR_UPDATE_OUTBOUND\n" + script
                script += '[ "${KEEN_PBR_UPDATE_OUTBOUND+x}" != x ] || exit 18\n'
            args = '"https://example.com/file" "/tmp/mock.ipk"' if function == "fetch" else '"/tmp/mock.ipk" "https://example.com/file"'
            environment = {key: value for key, value in os.environ.items() if key != "KEEN_PBR_UPDATE_OUTBOUND"}
            if override is not None:
                environment["KEEN_PBR_UPDATE_OUTBOUND"] = override
            return subprocess.run([BUSYBOX, "sh", "-c", script + function + " " + args], env=environment, text=True, capture_output=True, timeout=10)

    def test_panel_and_console_preserve_selection_and_fail_closed(self):
        sources = [(ROOT / "install.sh", "fetch"), (ROOT / "packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr/self-update.sh", "fetch_url")]
        for source, function in sources:
            for override, preference in [("group", False), ("", False), (None, True)]:
                with self.subTest(source=source.name, override=override, preference=preference):
                    result = self.run_fetch(source, function, override, preference)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("bound:fetch-update:https://example.com/file:/tmp/mock.ipk:", result.stdout)
                    self.assertTrue(result.stdout.rstrip("\n").endswith(":" + (override if override is not None else "unset")))
                    self.assertNotIn("unbound", result.stdout)
                    failed = self.run_fetch(source, function, override, preference, True)
                    self.assertEqual(failed.returncode, 17, failed.stderr)
                    self.assertNotIn("unbound", failed.stdout)
            bootstrap = self.run_fetch(source, function, None)
            self.assertEqual(bootstrap.returncode, 0, bootstrap.stderr)
            self.assertEqual(bootstrap.stdout.strip(), "unbound")

    def test_unusable_bound_helper_never_falls_back_to_curl(self):
        sources = [(ROOT / "install.sh", "fetch"), (ROOT / "packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr/self-update.sh", "fetch_url")]
        for source, function in sources:
            for override, preference in [("group", False), (None, True), (None, "symlink")]:
                with self.subTest(source=source.name, override=override, preference=preference):
                    result = self.run_fetch(source, function, override, preference, missing_binary=True)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertNotIn("unbound", result.stdout)
            # Even a dangling preference must reach validation, never bootstrap curl.
            result = self.run_fetch(source, function, None, "symlink", failure=True)
            self.assertEqual(result.returncode, 17, result.stderr)
            self.assertNotIn("unbound", result.stdout)

    def test_preference_is_independent_of_package_snapshots_and_routing_apply(self):
        api = (ROOT / "src/api/handler_health_service.cpp").read_text()
        save = api.split('server.post("/api/system/update/transport"', 1)[1].split(
            'server.post("/api/system/update/channel"', 1)[0]
        self.assertIn("save_update_outbound(kUpdateOutboundPreference, outbound)", save)
        for forbidden in ("std::system", "apply_config", "create_full_rollback_backup", "download_latest_release"):
            self.assertNotIn(forbidden, save)
        package = ROOT / "packages/keenetic/keen-pbr"
        self.assertNotIn("files/opt/etc/keen-pbr/update-outbound", (package / "Makefile").read_text())
        rescue = (package / "files/opt/usr/lib/keen-pbr/rescue-update.sh").read_text()
        self.assertNotIn("update-outbound", rescue.split("managed_config_files() {", 1)[1].split("\n}", 1)[0])

    def test_old_installer_cannot_ignore_selected_vpn(self):
        text = (ROOT / "packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr/self-update.sh").read_text(encoding="utf8")
        guard = text.split("# An older, even correctly signed installer", 1)[1].split('if [ -n "${EXPECTED_VERSION:-}" ]; then', 1)[0]
        guard = "# An older, even correctly signed installer" + guard
        with tempfile.TemporaryDirectory(prefix="kpbr-old-installer-") as temporary:
            installer = Path(temporary) / "install.sh"
            preference = Path(temporary) / "preference"
            guard = guard.replace("/opt/etc/keen-pbr/update-outbound", str(preference))
            for supported in (False, True):
                installer.write_text("#!/bin/sh\n" + ("KEEN_PBR_UPDATE_TRANSPORT_VERSION=1\n" if supported else ""))
                for saved in ("", "group"):
                    preference.write_text(saved + "\n")
                    for outbound in (None, "", "group"):
                        environment = {key: value for key, value in os.environ.items() if key != "KEEN_PBR_UPDATE_OUTBOUND"}
                        environment["INSTALLER"] = str(installer)
                        if outbound is not None:
                            environment["KEEN_PBR_UPDATE_OUTBOUND"] = outbound
                        result = subprocess.run([BUSYBOX, "sh", "-c", guard], env=environment, capture_output=True, text=True, timeout=5)
                        selected = saved if outbound is None else outbound
                        self.assertEqual(result.returncode, 1 if selected and not supported else 0, result.stderr)


if __name__ == "__main__":
    unittest.main()

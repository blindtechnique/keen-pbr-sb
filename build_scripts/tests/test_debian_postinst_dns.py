"""Exercise Debian postinst DNS choices using isolated paths and fake services."""

import contextlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
POSTINSTS = (
    "packages/debian/full/debian/keen-pbr.postinst",
    "packages/debian/headless/debian/keen-pbr-headless.postinst",
    "packages/debian/files/DEBIAN/postinst",
)
BUSYBOX = os.environ.get("BUSYBOX") or shutil.which("busybox")


class DebianPostinstDnsTest(unittest.TestCase):
    @contextlib.contextmanager
    def fixture(self, relative):
        with tempfile.TemporaryDirectory(prefix="kpbr-debian-dns-") as directory:
            root = Path(directory)
            (root / "bin").mkdir()
            (root / "lib").mkdir()
            self.root = root
            self.config = root / "dnsmasq.conf"
            self.backup = root / "dnsmasq.conf.backup-pre-keen-pbr"
            self.template = root / "lib/dnsmasq.conf.template"
            self.template.write_text("# package defaults\nserver=198.51.100.53\n")
            self.services = root / "service-calls"
            service = root / "bin/systemctl"
            service.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$SERVICE_CALLS"\n')
            service.chmod(0o755)
            self.script = root / "postinst"
            self.script.write_text(
                (ROOT / relative).read_text()
                .replace("/usr/lib/keen-pbr", str(root / "lib"))
                .replace("/etc/dnsmasq.conf", str(self.config))
            )
            self.environment = {
                **os.environ,
                "PATH": str(root / "bin") + os.pathsep + os.environ.get("PATH", ""),
                "DEBIAN_FRONTEND": "noninteractive",
                "SERVICE_CALLS": str(self.services),
            }
            self.environment.pop("KEEN_PBR_REPLACE_DNSMASQ_DEFAULTS", None)
            yield

    def variants(self):
        shells = (["/bin/sh"],)
        if BUSYBOX:
            shells += ([BUSYBOX, "sh"],)
        for relative in POSTINSTS:
            for shell in shells:
                yield relative, shell

    def run_postinst(self, shell, previous=None, answer=None, action="configure"):
        env = dict(self.environment)
        if answer is not None:
            env["KEEN_PBR_REPLACE_DNSMASQ_DEFAULTS"] = answer
        args = [*shell, str(self.script), action]
        if previous is not None:
            args.append(previous)
        result = subprocess.run(
            args, env=env, text=True, capture_output=True, timeout=10
        )
        return result

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_upgrade_preserves_current_config_and_original_backup_repeatedly(self):
        for relative, shell in self.variants():
            with self.subTest(relative=relative, shell=shell), self.fixture(relative):
                self.config.write_text("server=192.0.2.53\n")
                self.backup.write_text("# original operator configuration\n")
                for previous in ("3.3.1", "3.3.2"):
                    self.assert_success(self.run_postinst(shell, previous=previous))
                    self.assertEqual(self.config.read_text(), "server=192.0.2.53\n")
                    self.assertEqual(self.backup.read_text(), "# original operator configuration\n")
                self.assertEqual(len(list(self.root.glob("dnsmasq.conf.backup*"))), 1)

    def test_noninteractive_first_install_keeps_existing_configuration(self):
        for relative, shell in self.variants():
            with self.subTest(relative=relative, shell=shell), self.fixture(relative):
                self.config.write_text("server=192.0.2.53\n")
                self.assert_success(self.run_postinst(shell))
                self.assertEqual(self.config.read_text(), "server=192.0.2.53\n")
                self.assertFalse(self.backup.exists())

    def test_missing_configuration_gets_defaults_on_install_and_upgrade(self):
        for relative, shell in self.variants():
            for previous in (None, "3.3.1"):
                with self.subTest(relative=relative, shell=shell, previous=previous), self.fixture(relative):
                    self.assert_success(self.run_postinst(shell, previous=previous))
                    self.assertEqual(self.config.read_bytes(), self.template.read_bytes())
                    self.assertFalse(self.backup.exists())

    def test_explicit_replacement_keeps_every_previous_configuration(self):
        for relative, shell in self.variants():
            with self.subTest(relative=relative, shell=shell), self.fixture(relative):
                self.config.write_text("# original\n")
                self.assert_success(self.run_postinst(shell, previous="3.3.1", answer="Y"))
                self.assertEqual(self.backup.read_text(), "# original\n")
                self.config.write_text("# later operator edits\n")
                self.assert_success(self.run_postinst(shell, previous="3.3.2", answer="Y"))
                self.assertEqual(self.config.read_bytes(), self.template.read_bytes())
                self.assertEqual(self.backup.read_text(), "# original\n")
                extra = list(self.root.glob("dnsmasq.conf.backup-pre-keen-pbr.*"))
                self.assertEqual(len(extra), 1)
                self.assertEqual(extra[0].read_text(), "# later operator edits\n")

    def test_explicit_keep_overrides_missing_config_default(self):
        for relative, shell in self.variants():
            with self.subTest(relative=relative, shell=shell), self.fixture(relative):
                self.assert_success(self.run_postinst(shell, answer="N"))
                self.assertFalse(self.config.exists())
                self.assertFalse(self.backup.exists())

    def test_upgrade_does_not_prompt_when_frontend_is_not_noninteractive(self):
        for relative, shell in self.variants():
            with self.subTest(relative=relative, shell=shell), self.fixture(relative):
                self.environment.pop("DEBIAN_FRONTEND")
                self.config.write_text("# keep on upgrade\n")
                result = self.run_postinst(shell, previous="3.3.1")
                self.assert_success(result)
                self.assertNotIn("[y/n]", result.stdout)
                self.assertEqual(self.config.read_text(), "# keep on upgrade\n")

    def test_nonconfigure_actions_leave_dns_and_services_untouched(self):
        for relative, shell in self.variants():
            for action in ("abort-upgrade", "abort-remove", "abort-deconfigure", "triggered"):
                with self.subTest(relative=relative, shell=shell, action=action), self.fixture(relative):
                    self.config.write_text("# keep on abort\n")
                    self.assert_success(self.run_postinst(shell, action=action, answer="Y"))
                    self.assertEqual(self.config.read_text(), "# keep on abort\n")
                    self.assertFalse(self.backup.exists())
                    self.assertFalse(self.services.exists())

    def test_invalid_explicit_choice_does_not_replace_configuration(self):
        for relative, shell in self.variants():
            with self.subTest(relative=relative, shell=shell), self.fixture(relative):
                self.config.write_text("# keep invalid choice\n")
                self.assert_success(self.run_postinst(shell, answer="invalid"))
                self.assertEqual(self.config.read_text(), "# keep invalid choice\n")

    def test_absent_template_does_not_touch_existing_config(self):
        for relative, shell in self.variants():
            with self.subTest(relative=relative, shell=shell), self.fixture(relative):
                self.template.unlink()
                self.config.write_text("# no template\n")
                self.assert_success(self.run_postinst(shell, answer="Y"))
                self.assertEqual(self.config.read_text(), "# no template\n")
                self.assertFalse(self.backup.exists())

    def test_all_package_variants_share_the_same_policy(self):
        reference = (ROOT / POSTINSTS[0]).read_text()
        for relative in POSTINSTS[1:]:
            self.assertEqual(reference, (ROOT / relative).read_text())


if __name__ == "__main__":
    unittest.main()

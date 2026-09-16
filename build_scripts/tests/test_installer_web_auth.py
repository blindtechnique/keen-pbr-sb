"""Installer password choices and auth-only recovery; real BusyBox, no router."""

import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
INSTALLER = Path(os.environ.get("KPBR_TEST_INSTALLER", ROOT / "install.sh"))
SOURCE = INSTALLER.read_text(encoding="utf8")
BUSYBOX = shutil.which("busybox")


def function(name):
    start = SOURCE.index(name + "() {\n")
    return SOURCE[start:SOURCE.index("\n}\n", start) + 3]


@unittest.skipUnless(BUSYBOX, "BusyBox required")
class InstallerWebAuthTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="kpbr-auth-setup-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.opt = self.root / "opt"
        self.config = self.opt / "etc/keen-pbr"
        self.config.mkdir(parents=True)
        self.work = self.root / "work"
        self.work.mkdir()
        self.auth = self.config / "auth.json"
        self.auth.write_text('{"enabled":false}\n')
        self.original = self.auth.read_bytes()
        self.routing = self.config / "config.json"
        self.routing.write_text('{"operator-config":"unchanged"}\n')
        self.effects = self.root / "effects"
        self.answers = self.root / "answers"
        self.secrets = self.root / "secrets"
        self.count = self.root / "verify-count"
        self.count.write_text("0\n")
        self.init = self.opt / "etc/init.d/S80keen-pbr"
        self.helper = self.opt / "var/lib/keen-pbr/rescue/rescue-update.sh"
        self.executable(self.init, f'''
echo "core $1" >> '{self.effects}'
[ "${{TEST_RESTART_FAIL:-0}}" != 1 ]
''')
        self.executable(self.helper, f'''
echo "rescue $1" >> '{self.effects}'
count=$(cat '{self.count}')
count=$((count + 1))
echo "$count" > '{self.count}'
[ "$count" -gt "${{TEST_SLOW_VERIFY:-0}}" ] || exit 1
[ "${{TEST_VERIFY_FAIL:-0}}" != 1 ]
''')
        self.executable(self.opt / "etc/init.d/S79transport-manager",
                        f'echo "transport $1" >> "{self.effects}"')

    @staticmethod
    def executable(path, body):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/sh\nset -eu\n" + body + "\n")
        path.chmod(0o755)

    def overrides(self):
        return f'''
id() {{
    if [ "$1" = -u ]; then printf '%s\\n' "${{TEST_UID:-0}}";
    else command id "$@"; fi
}}
ask() {{
    echo "ask $1" >> '{self.effects}'
    IFS= read -r answer < '{self.answers}' || return 1
    sed -i '1d' '{self.answers}'
    printf '%s' "${{answer:-$2}}"
}}
ask_secret() {{
    echo "secret prompt" >> '{self.effects}'
    IFS= read -r answer < '{self.secrets}' || return 1
    sed -i '1d' '{self.secrets}'
    printf '%s' "$answer"
}}
acquire_update_lock() {{ echo lock >> '{self.effects}'; }}
detect_target() {{ echo forbidden-detect >> '{self.effects}'; exit 90; }}
ensure_release_verifier() {{ echo forbidden-download >> '{self.effects}'; exit 91; }}
'''

    def run_setup(self, answers=("1",), secrets=(), args=None, env=None):
        self.answers.write_text("".join(item + "\n" for item in answers))
        self.secrets.write_text("".join(item + "\n" for item in secrets))
        if args is None:
            script = ("set -eu\numask 077\n"
                      f"TMP_DIR='{self.work}'\nRESCUE_HELPER='{self.helper}'\n" +
                      "\n".join(function(name) for name in
                                ("say", "die", "verify_installed_runtime", "configure_web_auth")) +
                      self.overrides() + "\nconfigure_web_auth\n")
        else:
            anchor = '\nchoose_install_language\n'
            self.assertEqual(SOURCE.count(anchor), 1)
            script = SOURCE.replace(anchor, "\n" + self.overrides() +
                                    "\nchoose_install_language() { :; }\n" + anchor, 1)
        script = script.replace("/opt/", str(self.opt) + "/")
        # Fixture-derived absolute paths already contain /opt/; don't map twice.
        script = script.replace(str(self.root) + str(self.opt), str(self.opt))
        path = self.root / "installer.sh"
        path.write_text(script)
        return subprocess.run([BUSYBOX, "sh", str(path), *(args or [])],
                              capture_output=True, text=True, timeout=10,
                              env={**os.environ, "TMPDIR": str(self.work), **(env or {})})

    def effect_lines(self):
        return self.effects.read_text().splitlines() if self.effects.exists() else []

    def assert_router_auth(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        saved = json.loads(self.auth.read_text())
        self.assertIs(saved["enabled"], True)
        self.assertEqual(saved["provider"], "keenetic")
        self.assertEqual(saved["keenetic_endpoint_mode"], "auto")
        self.assertNotIn("password", saved)
        self.assertNotIn("username", saved)
        self.assertEqual(stat.S_IMODE(self.auth.stat().st_mode), 0o600)
        self.assertEqual(self.effect_lines().count("core restart"), 1)

    def test_default_uses_router_credentials_without_prompting_for_password(self):
        result = self.run_setup(answers=("",))
        self.assert_router_auth(result)
        self.assertNotIn("secret prompt", self.effect_lines())

    def test_disabled_existing_auth_is_replaced_not_preserved(self):
        result = self.run_setup()
        self.assert_router_auth(result)
        self.assertFalse(any("Сохранить существующие" in line for line in self.effect_lines()))
        backups = list(self.config.glob("auth.json.before-installer.*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), self.original)
        self.assertEqual(stat.S_IMODE(backups[0].stat().st_mode), 0o600)

    def test_first_install_without_auth_file(self):
        self.auth.unlink()
        self.assert_router_auth(self.run_setup())
        self.assertEqual(list(self.config.glob("auth.json.before-installer.*")), [])

    def test_invalid_and_old_no_password_answers_reprompt(self):
        self.assert_router_auth(self.run_setup(answers=("n", "0", "3", "no", "1")))
        self.assertEqual(sum("Выберите [1-2]" in line for line in self.effect_lines()), 5)

    def test_separate_credentials_escape_quotes_backslashes_and_utf8(self):
        username = 'user"\\тест'
        password = 'p"\\аss $ecret'
        result = self.run_setup(answers=("2", username), secrets=(password, password))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        saved = json.loads(self.auth.read_text())
        self.assertEqual((saved["enabled"], saved["provider"], saved["username"], saved["password"]),
                         (True, "local", username, password))
        self.assertNotIn(password, result.stdout + result.stderr)
        self.assertEqual(stat.S_IMODE(self.auth.stat().st_mode), 0o600)

    def test_blank_password_reprompts_instead_of_disabling_auth(self):
        result = self.run_setup(answers=("2", ""), secrets=("", "chosen-password", "chosen-password"))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        saved = json.loads(self.auth.read_text())
        self.assertEqual((saved["enabled"], saved["username"], saved["password"]),
                         (True, "admin", "chosen-password"))

    def test_mismatched_password_reprompts(self):
        result = self.run_setup(answers=("2", "admin"), secrets=("first", "typo", "second", "second"))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(self.auth.read_text())["password"], "second")

    def test_control_characters_reprompt_without_writing_invalid_json(self):
        result = self.run_setup(answers=("2", "bad\tname", "admin"),
                                secrets=("bad\tpassword", "valid", "valid"))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        saved = json.loads(self.auth.read_text())
        self.assertEqual((saved["username"], saved["password"]), ("admin", "valid"))

    def test_interrupted_password_input_preserves_previous_auth_and_services(self):
        for secrets in ((), ("",), ("password-without-confirmation",)):
            with self.subTest(secrets_count=len(secrets)):
                result = self.run_setup(answers=("2", "admin"), secrets=secrets)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.auth.read_bytes(), self.original)
                self.assertNotIn("core restart", self.effect_lines())

    def test_slow_restart_waits_without_another_restart(self):
        result = self.run_setup(env={"TEST_SLOW_VERIFY": "1"})
        self.assert_router_auth(result)
        self.assertEqual(self.effect_lines().count("rescue verify"), 2)

    def test_restart_failure_does_not_claim_panel_ready(self):
        result = self.run_setup(env={"TEST_RESTART_FAIL": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("Вход настроен:", result.stdout)
        self.assertIs(json.loads(self.auth.read_text())["enabled"], True)

    def test_readiness_timeout_retains_auth_and_does_not_stop_services(self):
        result = self.run_setup(env={"TEST_VERIFY_FAIL": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("Вход настроен:", result.stdout)
        self.assertIs(json.loads(self.auth.read_text())["enabled"], True)
        self.assertEqual(self.effect_lines().count("rescue verify"), 3)
        self.assertNotIn("core stop", self.effect_lines())

    def test_installed_helper_is_used_if_rescue_copy_is_missing(self):
        installed = self.opt / "usr/lib/keen-pbr/rescue-update.sh"
        installed.parent.mkdir(parents=True)
        self.helper.rename(installed)
        self.assert_router_auth(self.run_setup())

    def test_auth_only_full_entrypoint_skips_all_install_and_optional_setup(self):
        result = self.run_setup(args=("--configure-auth",))
        self.assert_router_auth(result)
        self.assertIn("Пакет, настройки DNS, VPN и nfqws2 не изменены.", result.stdout)
        self.assertIn("lock", self.effect_lines())
        self.assertEqual(self.routing.read_text(), '{"operator-config":"unchanged"}\n')
        self.assertFalse(any(line.startswith(("forbidden", "transport")) for line in self.effect_lines()))
        self.assertEqual(list(self.work.iterdir()), [])

    def test_auth_only_requires_existing_install_without_starting_installation(self):
        self.init.unlink()
        result = self.run_setup(args=("--configure-auth",))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.auth.read_bytes(), self.original)
        self.assertEqual(self.effect_lines(), ["lock"])

    def test_auth_only_rejects_non_root_before_any_mutation(self):
        result = self.run_setup(args=("--configure-auth",), env={"TEST_UID": "1000"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("root", result.stdout + result.stderr)
        self.assertEqual(self.auth.read_bytes(), self.original)
        self.assertEqual(self.effect_lines(), [])
        self.assertEqual(list(self.work.iterdir()), [])

    def test_auth_only_cannot_be_combined_with_update(self):
        result = self.run_setup(args=("--configure-auth", "--update"))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.auth.read_bytes(), self.original)
        self.assertEqual(self.effect_lines(), [])

    def test_update_entrypoint_preserves_existing_auth_without_prompting(self):
        start = SOURCE.index('\nif [ "$UPDATE_ONLY" = "1" ]; then\n    say "Устанавливаю обновление')
        tail = SOURCE[start:]
        script = ('set -eu\nUPDATE_ONLY=1\nsay() { :; }\n'
                  'install_package_transactionally() { :; }\n'
                  'configure_web_auth() { exit 91; }\n' + tail)
        result = subprocess.run([BUSYBOX, "sh", "-c", script], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.auth.read_bytes(), self.original)


if __name__ == "__main__":
    unittest.main(verbosity=2)

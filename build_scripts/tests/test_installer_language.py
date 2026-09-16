"""Exercise real BusyBox prompts on a controlling terminal; no router writes."""

import os
from pathlib import Path
import select
import shutil
import subprocess
import tempfile
import time
import unittest

try:
    import pty
except ImportError:
    pty = None

ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "install.sh").read_text(encoding="utf8")
BUSYBOX = shutil.which("busybox")


def function(name):
    start = SOURCE.index(name + "() {\n")
    return SOURCE[start:SOURCE.index("\n}\n", start) + 3]


@unittest.skipUnless(BUSYBOX and pty, "BusyBox and a POSIX PTY required")
class InstallerLanguageTest(unittest.TestCase):
    def run_terminal(self, replies, tail):
        definitions = "\n".join(function(name) for name in
                                ("say", "ask", "choose_install_language", "ask_dns_setup"))
        script = "set -eu\nUPDATE_ONLY=0\nINSTALL_LANGUAGE=ru\n" + definitions + "\n" + tail
        with tempfile.TemporaryDirectory(prefix="kpbr-language-") as directory:
            path = Path(directory) / "prompts.sh"
            path.write_text(script)
            pid, terminal = pty.fork()
            if pid == 0:
                os.execv(BUSYBOX, [BUSYBOX, "sh", str(path)])
            output = b""
            sent = 0
            deadline = time.monotonic() + 10
            try:
                while time.monotonic() < deadline:
                    if not select.select([terminal], [], [], 0.1)[0]:
                        continue
                    try:
                        part = os.read(terminal, 4096)
                    except OSError:
                        break
                    if not part:
                        break
                    output += part
                    if sent < len(replies):
                        prompt, answer = replies[sent]
                        if output.count(prompt.encode()) > sum(
                                previous[0] == prompt for previous in replies[:sent]):
                            os.write(terminal, (answer + "\n").encode())
                            sent += 1
                else:
                    os.kill(pid, 9)
                    self.fail("prompt timed out: " + output.decode(errors="replace"))
            finally:
                os.close(terminal)
                _, status = os.waitpid(pid, 0)
            self.assertEqual(status, 0, output.decode(errors="replace"))
            self.assertEqual(sent, len(replies))
            return output.decode()

    def test_english_warning_precedes_dns_prompt_and_answer_is_not_polluted(self):
        output = self.run_terminal(
            [("[1/2]:", "2"), ("dnsmasq? [Y/n]:", "N")],
            'choose_install_language\nanswer=$(ask_dns_setup)\nprintf "RESULT=<%s>\\n" "$answer"')
        self.assertTrue(output.startswith("Язык / Language:"))
        self.assertLess(output.index("will not work fully"), output.index("Enable Keenetic DNS"))
        self.assertIn("RESULT=<N>", output)
        self.assertNotIn("Если выбрать", output)

    def test_russian_default_and_invalid_language_reprompt(self):
        output = self.run_terminal(
            [("[1/2]:", "invalid"), ("[1/2]:", ""), ("Entware? [Y/n]:", "")],
            'choose_install_language\nanswer=$(ask_dns_setup)\nprintf "RESULT=<%s>\\n" "$answer"')
        self.assertIn("Enter 1 or 2", output)
        self.assertLess(output.index("не будет работать полноценно"), output.index("Включить Keenetic"))
        self.assertIn("RESULT=<Y>", output)
        self.assertNotIn("If you choose", output)

    def test_update_never_asks_for_a_language_without_a_terminal(self):
        script = ("set -eu\nUPDATE_ONLY=1\n" + function("choose_install_language") +
                  '\nask() { exit 91; }\nchoose_install_language\necho done\n')
        result = subprocess.run([BUSYBOX, "sh", "-c", script], capture_output=True,
                                text=True, timeout=3, start_new_session=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "done\n")

    def test_language_choice_is_before_all_installation_actions(self):
        tail = SOURCE[SOURCE.index("\nchoose_install_language\n"):]
        self.assertLess(tail.index("choose_install_language"), tail.index("acquire_update_lock"))
        self.assertLess(tail.index("choose_install_language"), tail.index("detect_target"))
        self.assertLess(tail.index("choose_install_language"), tail.index("configure_web_auth"))


if __name__ == "__main__":
    unittest.main(verbosity=2)

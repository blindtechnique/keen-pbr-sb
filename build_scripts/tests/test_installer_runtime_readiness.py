"""Real-time first-boot probe regression; isolated container, no router access.

Uses S79/S80 and rescue/update-lock/metadata helpers from the released IPK,
Entware's rc.func, real process identities and GNU wget against a real HTTP
listener. Only the daemon's body is substituted: an AArch64 Keenetic daemon
and its firmware/kernel are NOT emulated by this test.
"""

import http.server
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest


ROOT = Path(__file__).resolve().parents[2]
IPK = os.environ.get("KPBR_TEST_IPK")
RC_IPK = os.environ.get("KPBR_TEST_RC_IPK")
BUSYBOX = shutil.which("busybox")


def package_files(path):
    with tarfile.open(path, "r:gz") as outer:
        data = outer.extractfile("./data.tar.gz").read()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as payload:
        return {member.name.removeprefix("./"): payload.extractfile(member).read()
                for member in payload if member.isfile()}


@unittest.skipUnless(IPK and RC_IPK and BUSYBOX and Path("/.dockerenv").exists(),
                     "published IPKs and isolated BusyBox container required")
class PublishedReadinessTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="kpbr-real-ready-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.opt = self.root / "opt"
        self.rescue = self.opt / "var/lib/keen-pbr/rescue"
        self.rescue.mkdir(parents=True, mode=0o700)
        for part in ("bin", "usr/bin", "etc/init.d", "etc/keen-pbr", "var/run", "var/log", "usr/lib/keen-pbr"):
            (self.opt / part).mkdir(parents=True, exist_ok=True)
        files = package_files(IPK)
        for name in ("rescue-update.sh", "update-lock.sh", "portable-stat.sh", "lifecycle-lock.sh"):
            body = files["opt/usr/lib/keen-pbr/" + name]
            # Helpers have their own explicit test-root support: no text edits.
            self.write(self.opt / "usr/lib/keen-pbr" / name, body)
            if name != "lifecycle-lock.sh":
                self.write(self.rescue / name, body)
        for name in ("S80keen-pbr", "S79transport-manager"):
            body = files["opt/etc/init.d/" + name].decode().replace("/opt/", str(self.opt) + "/")
            self.write(self.opt / "etc/init.d" / name, body.encode())
        defaults = files["opt/etc/keen-pbr/defaults"].decode().replace("/opt/", str(self.opt) + "/")
        self.write(self.opt / "etc/keen-pbr/defaults", defaults.encode())
        self.write(self.opt / "etc/init.d/rc.func", package_files(RC_IPK)["opt/etc/init.d/rc.func"])
        self.config = json.loads(files["opt/etc/keen-pbr/config.json"])
        wget = shutil.which("wget")
        version = subprocess.run([wget, "--version"], capture_output=True, text=True)
        self.assertIn("GNU Wget", version.stdout, "this regression must cover wget-ssl, not a mock")
        (self.opt / "bin/wget").symlink_to(wget)
        self.env = {**os.environ, "KEEN_PBR_RESCUE_ROOT": str(self.root), "PATH": "/usr/bin:/bin"}
        for key in ("KEEN_PBR_UPDATE_LOCK_PID", "KEEN_PBR_UPDATE_LOCK_TOKEN"):
            self.env.pop(key, None)
        self.processes = []
        self.addCleanup(self.stop_processes)
        for name in ("keen-pbr", "transport-manager"):
            code = ("import ctypes,time; "
                    f"ctypes.CDLL(None).prctl(15, {name.encode()!r}, 0, 0, 0); "
                    "time.sleep(240)")
            process = subprocess.Popen([str(self.opt / "usr/bin" / name), "-c", code, "service"],
                                       executable=sys.executable)
            self.processes.append(process)
            if name == "keen-pbr":
                (self.opt / "var/run/keen-pbr.pid").write_text(str(process.pid) + "\n")
        time.sleep(0.15)
        self.assert_services_alive()

    @staticmethod
    def write(path, data):
        path.write_bytes(data)
        path.chmod(0o755)

    def stop_processes(self):
        for process in self.processes:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)

    def assert_services_alive(self):
        for name in ("S80keen-pbr", "S79transport-manager"):
            check = subprocess.run([str(self.opt / "etc/init.d" / name), "check"],
                                   env=self.env, capture_output=True, text=True, timeout=5)
            self.assertEqual(check.returncode, 0, name + ": " + check.stdout + check.stderr)
        self.assertTrue(all(process.poll() is None for process in self.processes))

    def probe_with_delayed_api(self, windows):
        requests = []
        began = time.monotonic()

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append((time.monotonic() - began, self.path))
                data = b'{"enabled":false,"authenticated":true,"trusted_local_connection":true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler, bind_and_activate=False)
        server.server_bind()  # Reserve the port, but connections are refused until listen().
        self.config["api"]["listen"] = "0.0.0.0:" + str(server.server_port)
        (self.opt / "etc/keen-pbr/config.json").write_text(json.dumps(self.config))
        cancelled = threading.Event()
        listening = threading.Event()

        def serve():
            if cancelled.wait(33):
                return
            server.server_activate()
            listening.set()
            server.serve_forever(poll_interval=0.05)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        source = Path(os.environ.get("KPBR_TEST_INSTALLER", ROOT / "install.sh")).read_text()
        start = source.index("verify_installed_runtime() {\n")
        function = source[start:source.index("\n}\n", start) + 3]
        function = function.replace("/opt/", str(self.opt) + "/")
        script = (f"set -eu\nRESCUE_HELPER='{self.rescue}/rescue-update.sh'\n"
                  "say() { printf '%s\\n' \"$*\"; }\n" + function +
                  f"\nverify_installed_runtime {windows}\n")
        try:
            result = subprocess.run([BUSYBOX, "sh", "-c", script], env=self.env,
                                    capture_output=True, text=True, timeout=110)
            elapsed = time.monotonic() - began
        finally:
            cancelled.set()
            if listening.is_set():
                server.shutdown()
            thread.join(timeout=2)
            server.server_close()
        self.assert_services_alive()
        return result, elapsed, requests

    def test_33_second_boot_fails_old_window_but_passes_first_install_wait(self):
        # Baseline: exactly the published helper's single verification window.
        old, old_elapsed, old_requests = self.probe_with_delayed_api(windows=1)
        self.assertNotEqual(old.returncode, 0, old.stdout + old.stderr)
        self.assertGreaterEqual(old_elapsed, 29)
        self.assertEqual(old_requests, [])
        fixed, elapsed, requests = self.probe_with_delayed_api(windows=3)
        self.assertEqual(fixed.returncode, 0, fixed.stdout + fixed.stderr)
        self.assertGreaterEqual(elapsed, 37)
        self.assertLess(elapsed, 65)
        self.assertGreaterEqual(len(requests), 3)
        self.assertTrue(all(path == "/api/auth/status" for _, path in requests))
        self.assertGreaterEqual(requests[-1][0] - requests[-3][0], 3.8)
        self.assertIn("(2/3)", fixed.stdout)
        print(f"real probe: old rejected after {old_elapsed:.1f}s; "
              f"fixed passed after {elapsed:.1f}s; stable HTTP samples={len(requests)}; "
              "same daemon PIDs, no restart", flush=True)


if __name__ == "__main__":
    unittest.main()

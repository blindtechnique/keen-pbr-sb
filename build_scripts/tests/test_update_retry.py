"""Actual rescue shell against tiny fixture packages; never invokes real opkg."""
import io
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]
LIB = REPO / "packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr"


def archive(files):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as tar:
        for name, content in files.items():
            data = content.encode() if isinstance(content, str) else content
            entry = tarfile.TarInfo("./" + name)
            entry.size = len(data)
            entry.mode = 0o755
            tar.addfile(entry, io.BytesIO(data))
    return stream.getvalue()


@unittest.skipUnless(Path("/.dockerenv").exists(), "isolated Linux container required")
class UpdateRetryTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="kpbr-retry-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.rescue = self.root / "opt/var/lib/keen-pbr/rescue"
        self.rescue.mkdir(parents=True, mode=0o700)
        for name in ("rescue-update.sh", "update-lock.sh", "portable-stat.sh"):
            self.write("opt/var/lib/keen-pbr/rescue/" + name,
                       (LIB / name).read_text())
        init = ('#!/bin/sh\nprintf "%s\\n" "$*" >> "$KEEN_PBR_RESCUE_ROOT/service.log"\n'
                'case "$1" in check) exit 0 ;; *) exit 91 ;; esac\n')
        self.payload = {
            "opt/usr/bin/keen-pbr": "#!/bin/sh\nexit 0\n",
            "opt/usr/bin/transport-manager": "#!/bin/sh\nexit 0\n",
            "opt/usr/lib/keen-pbr/fixture-lib": "old package library\n",
            "opt/etc/init.d/S80keen-pbr": init,
            "opt/etc/init.d/S79transport-manager": init,
            "opt/etc/keen-pbr/config.json": '{"api":{"enabled":false}}\n',
        }
        for name, body in self.payload.items():
            self.write(name, body)
        self.write("opt/bin/opkg",
                   '#!/bin/sh\n[ "$*" = "status keen-pbr" ] || exit 92\n'
                   'cat "$KEEN_PBR_RESCUE_ROOT/package-status"\n')
        self.write("package-status", "Package: keen-pbr\nVersion: 1\nStatus: deinstall user installed\n")
        self.write("mock-bin/sleep", "#!/bin/sh\nexit 0\n")
        self.env = {**os.environ, "KEEN_PBR_RESCUE_ROOT": str(self.root),
                    "PATH": str(self.root / "mock-bin") + ":/usr/bin:/bin"}
        for key in ("KEEN_PBR_UPDATE_LOCK_PID", "KEEN_PBR_UPDATE_LOCK_TOKEN"):
            self.env.pop(key, None)
        baseline = self.package("old", "1", self.payload)
        self.assertEqual(self.run_helper("stage", str(baseline)).returncode, 0)
        self.assertEqual(self.run_helper("promote").returncode, 0)
        newer = {**self.payload, "opt/usr/bin/keen-pbr": "#!/bin/sh\nexit 2\n"}
        candidate = self.package("new", "2", newer)
        self.assertEqual(self.run_helper("stage", str(candidate)).returncode, 0)
        self.write("opt/var/lib/keen-pbr/rescue/UNKNOWN", "failed prerm and compensation\n")
        # A later edit MUST survive retry; pre-update-config is intentionally old.
        self.config = self.root / "opt/etc/keen-pbr/config.json"
        self.latest_config = '{"api":{"enabled":false},"description":"edited after failure"}\n'
        self.config.write_text(self.latest_config)

    def write(self, name, body):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
        path.chmod(0o755)
        return path

    def package(self, name, version, payload):
        control = archive({"control": f"Package: keen-pbr\nVersion: {version}\n",
                           "conffiles": "/opt/etc/keen-pbr/config.json\n"})
        path = self.root / (name + ".fixture")
        path.write_bytes(archive({"control.tar.gz": control,
                                  "data.tar.gz": archive(payload)}))
        return path

    def run_helper(self, *args):
        return subprocess.run(["/bin/sh", str(self.rescue / "rescue-update.sh"), *args],
                              env=self.env, capture_output=True, text=True, timeout=30)

    def test_intact_baseline_retires_failed_attempt_without_restore_or_restart(self):
        result = self.run_helper("prepare-update")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.rescue / "UNKNOWN").exists())
        self.assertFalse((self.rescue / "pending").exists())
        self.assertTrue((self.rescue / "current.ipk").exists())
        self.assertEqual(self.config.read_text(), self.latest_config)
        self.assertEqual(set((self.root / "service.log").read_text().splitlines()), {"check"})
        self.assertEqual(self.run_helper("prepare-update").returncode, 0)

    def test_changed_library_is_not_mistaken_for_intact_package(self):
        self.write("opt/usr/lib/keen-pbr/fixture-lib", "partly replaced\n")
        self.assert_blocked()

    def test_changed_installed_version_is_not_mistaken_for_old_baseline(self):
        self.write("package-status", "Version: 2\nStatus: install ok installed\n")
        self.assert_blocked()

    def test_corrupt_baseline_remains_recoverable(self):
        with (self.rescue / "pending-baseline.ipk").open("ab") as stream:
            stream.write(b"corrupted")
        self.assert_blocked()

    def test_foreign_symlink_is_not_followed(self):
        file = self.root / "opt/usr/lib/keen-pbr/fixture-lib"
        saved = self.root / "same-bytes"
        shutil.copyfile(file, saved)
        file.unlink()
        file.symlink_to(saved)
        self.assert_blocked()

    def assert_blocked(self):
        result = self.run_helper("prepare-update")
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertTrue((self.rescue / "UNKNOWN").exists())
        self.assertTrue((self.rescue / "pending").exists())
        self.assertTrue((self.rescue / "pending-baseline.ipk").exists())
        self.assertEqual(self.config.read_text(), self.latest_config)


if __name__ == "__main__":
    unittest.main()

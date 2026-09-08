"""Run real installer functions against temporary binaries and fake opkg only."""

from pathlib import Path
import hashlib
import json
import shutil
import subprocess
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "install.sh").read_text()


def function(name):
    start = SOURCE.index(name + "() {\n")
    return SOURCE[start:SOURCE.index("\n}\n", start) + 3]


@unittest.skipUnless(shutil.which("busybox"), "BusyBox shell required")
class InstallerComponentPreservationTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="kpbr-installer-components-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.opt = self.root / "opt"
        self.work = self.root / "mykeenpbr-install.test"
        self.work.mkdir()
        for directory in ("bin", "lib", "etc/opkg", "etc/keen-pbr"):
            (self.opt / directory).mkdir(parents=True, exist_ok=True)
        self.binary = self.opt / "bin/sing-box"
        self.real = self.opt / "bin/sing-box.real"
        self.candidate = self.root / "candidate"
        self.feed = self.opt / "etc/opkg/nfqws2-keenetic.conf"
        self.old_feed = b"# custom feed\nsrc/gz nfqws2 https://example.test/custom\n"

    def executable(self, path, body):
        path.write_text("#!/bin/sh\n" + body + "\n")
        path.chmod(0o755)

    def old_pair(self):
        self.executable(self.binary, 'exec "$0.real" "$@"')
        self.executable(self.real, "echo old-working-version")
        self.before = (self.binary.read_bytes(), self.real.read_bytes())

    def loader(self):
        self.executable(self.opt / "lib/ld-test.so", 'shift 2\nexport TEST_LOADER=1\nexec "$@"')

    def run_shell(self, names, tail, overrides=""):
        body = "\n".join(function(name) for name in names)
        body = body.replace("/opt/", str(self.opt) + "/")
        script = f"""set -eu
TMP_DIR='{self.work}'
FALLBACK_CLEANUP_OWNED=0
LOCK_OWNED=0
UPDATE_ONLY=0
PROJECT_REPOSITORY=blindtechnique/keen-pbr-sb
TRUSTED_RELEASE_REPOSITORY=$PROJECT_REPOSITORY
say() {{ :; }}
die() {{ printf '%s\\n' "$*" >&2; exit 1; }}
{body}
{overrides}
{tail}
"""
        return subprocess.run([shutil.which("busybox"), "sh", "-c", script],
                              capture_output=True, text=True, timeout=10)

    def publish(self, overrides=""):
        return self.run_shell(
            ("make_entware_sing_box_wrapper", "publish_sing_box_candidate"),
            f"publish_sing_box_candidate '{self.candidate}'", overrides)

    def assert_old_pair(self):
        self.assertEqual((self.binary.read_bytes(), self.real.read_bytes()), self.before)
        result = subprocess.run([str(self.binary), "version"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "old-working-version")
        self.assertEqual(list((self.opt / "bin").glob(".keen-pbr-sing-box.*")), [])

    def test_bad_candidate_preserves_working_binary_and_wrapper(self):
        self.old_pair()
        self.executable(self.candidate, "exit 1")
        self.assertNotEqual(self.publish().returncode, 0)
        self.assert_old_pair()

    def test_bad_candidate_with_loader_preserves_old_pair(self):
        self.old_pair()
        self.loader()
        self.executable(self.candidate, "exit 1")
        self.assertNotEqual(self.publish().returncode, 0)
        self.assert_old_pair()

    def test_full_install_function_preserves_core_after_downloaded_candidate_fails(self):
        self.old_pair()
        self.executable(self.candidate, "exit 1")
        archive = self.root / "sing-box-1.13.14-linux-arm64.tar.gz"
        with tarfile.open(archive, "w:gz") as stream:
            stream.add(self.candidate, arcname="sing-box-1.13.14-linux-arm64/sing-box")
        sums = self.root / "checksums.txt"
        sums.write_text(hashlib.sha256(archive.read_bytes()).hexdigest() + "  " + archive.name + "\n")
        metadata = self.root / "release.json"
        metadata.write_text(json.dumps({"assets": [
            {"browser_download_url": "https://fixture/" + archive.name},
            {"browser_download_url": "https://fixture/sing-box-1.13.14-checksums.txt"},
        ]}))
        overrides = f"""SING_BOX_PINNED_VERSION=1.13.14
KEEN_ARCH=aarch64
GITHUB_API=https://fixture/api
fetch() {{
    case "$1" in
        *releases/tags*) cp '{metadata}' "$2";;
        *.tar.gz) cp '{archive}' "$2";;
        *checksums.txt) cp '{sums}' "$2";;
        *) exit 99;;
    esac
}}"""
        result = self.run_shell(("github_asset_urls", "make_entware_sing_box_wrapper",
                                 "publish_sing_box_candidate", "install_sing_box"),
                                "install_sing_box 1.13.14", overrides)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ABI", result.stderr)
        self.assert_old_pair()
        self.assertFalse((self.opt / "etc/keen-pbr/sing-box-managed.path").exists())

    def test_bad_candidate_on_first_install_leaves_no_binary(self):
        self.executable(self.candidate, "exit 1")
        self.assertNotEqual(self.publish().returncode, 0)
        self.assertFalse(self.binary.exists())
        self.assertFalse(self.real.exists())

    def test_candidate_copy_failure_preserves_old_pair(self):
        self.old_pair()
        self.executable(self.candidate, "echo new-version")
        fail_copy = f'cp() {{ [ "$1" != "{self.candidate}" ] || return 1; command cp "$@"; }}'
        self.assertNotEqual(self.publish(fail_copy).returncode, 0)
        self.assert_old_pair()

    def test_publication_failure_restores_pair(self):
        self.old_pair()
        self.loader()
        self.executable(self.candidate, '[ "${TEST_LOADER:-}" = 1 ] || exit 1\necho new-version')
        fault = self.root / "fault-fired"
        fail_move = f"""mv() {{
    for last do :; done
    if [ "$last" = '{self.binary}' ] && [ ! -f '{fault}' ]; then
        touch '{fault}'
        return 1
    fi
    command mv "$@"
}}"""
        self.assertNotEqual(self.publish(fail_move).returncode, 0)
        self.assertTrue(fault.exists())
        self.assert_old_pair()

    def test_failed_final_launch_restores_pair(self):
        self.old_pair()
        self.executable(self.candidate, 'case "$0" in */.keen-pbr-sing-box.*/sing-box) exit 0;; *) exit 1;; esac')
        self.assertNotEqual(self.publish().returncode, 0)
        self.assert_old_pair()

    def test_existing_symlink_and_its_target_survive_failed_publication(self):
        target = self.root / "user-sing-box"
        self.executable(target, "echo user-working-version")
        self.binary.symlink_to(target)
        before = target.read_bytes()
        self.executable(self.candidate, 'case "$0" in */.keen-pbr-sing-box.*/sing-box) exit 0;; *) exit 1;; esac')
        self.assertNotEqual(self.publish().returncode, 0)
        self.assertTrue(self.binary.is_symlink())
        self.assertEqual(self.binary.resolve(), target)
        self.assertEqual(target.read_bytes(), before)

    def test_good_direct_candidate_replaces_old_pair_and_removes_old_payload(self):
        self.old_pair()
        self.executable(self.candidate, "echo new-version")
        result = self.publish()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.real.exists())
        self.assertEqual(subprocess.check_output([str(self.binary), "version"], text=True).strip(), "new-version")

    def test_good_wrapped_candidate_still_works_after_stage_cleanup(self):
        self.old_pair()
        self.loader()
        self.executable(self.candidate, '[ "${TEST_LOADER:-}" = 1 ] || exit 1\necho new-wrapped-version')
        result = self.publish()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(subprocess.check_output([str(self.binary), "version"], text=True).strip(), "new-wrapped-version")
        self.assertEqual(list((self.opt / "bin").glob(".keen-pbr-sing-box.*")), [])

    def prepare_feed(self):
        self.feed.write_bytes(self.old_feed)
        self.feed.chmod(0o640)

    def repair(self, tail="repair_interrupted_nfqws_bootstrap", overrides=""):
        return self.run_shell(("cleanup", "repair_interrupted_nfqws_bootstrap", "ensure_release_verifier"),
                              "trap cleanup EXIT\ntrap 'exit 129' HUP\n" + tail, overrides)

    def test_feed_restored_when_update_or_install_fails(self):
        self.prepare_feed()
        for phase in ("update", "install"):
            with self.subTest(phase=phase):
                self.work.mkdir(exist_ok=True)
                self.executable(self.opt / "bin/opkg", f'[ "$1" != "{phase}" ] || exit 1\nexit 0')
                result = self.repair()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.feed.read_bytes(), self.old_feed)
                self.assertEqual(self.feed.stat().st_mode & 0o777, 0o640)
                self.assertFalse(self.work.exists())

    def test_feed_restored_after_successful_https_repair(self):
        self.prepare_feed()
        self.executable(self.opt / "bin/opkg", "exit 0")
        result = self.repair()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.feed.read_bytes(), self.old_feed)
        self.assertFalse(self.work.exists())

    def test_hangup_after_feed_move_restores_original(self):
        self.prepare_feed()
        self.executable(self.opt / "bin/opkg", "exit 0")
        fault = self.root / "move-interrupted"
        move_then_hangup = f"""mv() {{
    command mv "$@" || return 1
    if [ ! -f '{fault}' ]; then
        touch '{fault}'
        kill -HUP $$
    fi
}}"""
        result = self.repair(overrides=move_then_hangup)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.feed.read_bytes(), self.old_feed)
        self.assertFalse(self.work.exists())

    def test_existing_feed_does_not_block_openssl_bootstrap(self):
        self.prepare_feed()
        ssl = self.root / "ssl-ready"
        self.executable(self.opt / "bin/opkg", f"""case "$1" in
status) [ -f '{ssl}' ] && echo 'Status: install ok installed';;
update) if [ -f '{self.feed}' ] && [ ! -f '{ssl}' ]; then exit 1; fi;;
install) case "$*" in *wget-ssl*) touch '{ssl}';; esac;;
esac
exit 0""")
        # Exercise the real ordered block before the first verifier dependency.
        start = SOURCE.index('\nif [ "$UPDATE_ONLY" = "0" ]; then\n', SOURCE.index('\ndetect_target\n'))
        end = SOURCE.index('\nensure_release_verifier\n', start) + len('\nensure_release_verifier')
        result = self.repair(SOURCE[start:end], 'command() { return 1; }\nprepare_release_verifier() { :; }')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(ssl.exists())
        self.assertEqual(self.feed.read_bytes(), self.old_feed)

    def test_update_path_does_not_repair_optional_feed(self):
        start = SOURCE.index('\nif [ "$UPDATE_ONLY" = "0" ]; then\n', SOURCE.index('\ndetect_target\n'))
        end = SOURCE.index('\nensure_release_verifier\n', start) + len('\nensure_release_verifier')
        result = self.run_shell((), SOURCE[start:end],
            'UPDATE_ONLY=1\nrepair_interrupted_nfqws_bootstrap() { exit 99; }\nensure_release_verifier() { :; }')
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()

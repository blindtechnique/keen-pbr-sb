"""Offline signed-update wiring tests; no network, opkg, or service operations."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
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
INSTALLER = ROOT / "install.sh"
LIB = ROOT / "packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr"
VERIFIER = LIB / "release-verify.sh"
SELF_UPDATE = LIB / "self-update.sh"
EMBEDDER = ROOT / "build_scripts/embed-release-verifier.py"
PACKAGE = "keen-pbr_3.3.1-test_keenetic_aarch64-3.10.ipk"
REPOSITORY = "blindtechnique/keen-pbr-sb"
RELEASE = "v3.3.1"
BUSYBOX = os.environ.get("BUSYBOX") or shutil.which("busybox")


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def shell_function(text, name, next_name):
    return name + "() {" + text.split(name + "() {", 1)[1].split(
        "\n" + next_name + "() {", 1)[0]


@unittest.skipUnless(BUSYBOX, "BusyBox tar is required")
class InstallerBootstrapArchiveTest(unittest.TestCase):
    def test_gzip_ipk_helpers_extract_with_busybox_tar(self):
        source = INSTALLER.read_text(encoding="utf8")
        # Execute the real bootstrap extraction, stopping before helper execution
        # or publication under /opt. GNU tar's gzip autodetection hid this bug.
        extraction = source.split("bootstrap_rescue_helpers() {", 1)[1].split(
            '\n    rescue_source=', 1)[0]
        helpers = ("portable-stat.sh", "rescue-update.sh",
                   "rescue-startup-guard.sh", "update-lock.sh")
        content = b"#!/bin/sh\n# Extraction-only fixture; never executed.\n"
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w:gz") as archive:
            for helper in helpers:
                member = tarfile.TarInfo(f"./opt/usr/lib/keen-pbr/{helper}")
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
        payload = data.getvalue()

        with tempfile.TemporaryDirectory(prefix="kpbr-bootstrap-busybox-") as temporary:
            work = Path(temporary)
            package = work / PACKAGE
            with tarfile.open(package, mode="w:gz") as archive:
                member = tarfile.TarInfo("./data.tar.gz")
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
            script = r'''
set -eu
die() { printf '%s\n' "$*" >&2; exit 1; }
tar() { "$BUSYBOX" tar "$@"; }
''' + extraction
            result = subprocess.run(
                [BUSYBOX, "sh", "-c", script],
                env={**os.environ, "BUSYBOX": BUSYBOX, "TMP_DIR": str(work),
                     "PACKAGE_FILE": str(package)},
                capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((work / "data.tar.gz").read_bytes(), payload)
            for helper in helpers:
                self.assertEqual(
                    (work / "package-helpers/opt/usr/lib/keen-pbr" / helper).read_bytes(),
                    content)


@unittest.skipUnless(shutil.which("sh") and shutil.which("openssl"),
                     "POSIX shell and OpenSSL are required")
class SignedUpdateIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.TemporaryDirectory(prefix="kpbr-test-only-signing-")
        cls.key = Path(cls.keys.name) / "test-only-private.pem"
        cls.public_key = Path(cls.keys.name) / "test-only-public.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt",
                        "rsa_keygen_bits:3072", "-out", str(cls.key)],
                       check=True, capture_output=True, timeout=30)
        subprocess.run(["openssl", "pkey", "-in", str(cls.key), "-pubout", "-out",
                        str(cls.public_key)], check=True, capture_output=True, timeout=10)
        cls.signer = load_module("release_signer_integration",
                                 ROOT / "build_scripts/sign-keenetic-release.py")

    @classmethod
    def tearDownClass(cls):
        cls.keys.cleanup()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="kpbr-signed-integration-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.assets = self.root / "assets"
        self.assets.mkdir()
        self.work = self.root / "work"
        self.work.mkdir()
        (self.assets / PACKAGE).write_bytes(b"test fixture, not an installable IPK\n")
        self.source_installer = self.root / "trusted-fixture-installer.sh"
        self.source_installer.write_text(
            '#!/bin/sh\nprintf "%s\\n" "$KEEN_PBR_UPDATE_RELEASE_TAG" > "$WORK_DIR/executed"\n',
            encoding="utf8")
        self.args = argparse.Namespace(
            assets=self.assets, installer=self.source_installer, key=self.key,
            public_key=self.public_key, repository=REPOSITORY, channel="stable",
            release=RELEASE, source="a" * 40, build="3.3.1-test")
        self.signer.sign(self.args)

    def metadata(self):
        (self.assets / "metadata").write_text(json.dumps({
            "tag_name": RELEASE,
            "assets": [{"browser_download_url":
                        f"https://github.com/{REPOSITORY}/releases/download/{RELEASE}/{name}"}
                       for name in (PACKAGE, "SHA256SUMS")],
        }), encoding="utf8")
        digest = hashlib.sha256((self.assets / PACKAGE).read_bytes()).hexdigest()
        (self.assets / "SHA256SUMS").write_text(f"{digest}  {PACKAGE}\n", encoding="utf8")

    def run_shell(self, script, **variables):
        env = {**os.environ, "WORK_DIR": str(self.work), "TMP_DIR": str(self.work),
               "FIXTURE_ASSETS": str(self.assets), "RELEASE_VERIFIER": str(VERIFIER),
               "RELEASE_PUBLIC_KEY": str(self.public_key), **variables}
        return subprocess.run(["sh", "-c", script], env=env,
                              capture_output=True, text=True, timeout=15)

    def download(self, repository=REPOSITORY):
        self.metadata()
        source = INSTALLER.read_text(encoding="utf8")
        functions = shell_function(source, "github_asset_urls", "detect_target") + "\n" + \
            shell_function(source, "download_package", "bootstrap_rescue_helpers")
        script = r'''
set -eu
REQUESTED_RELEASE_TAG=v3.3.1
TRUSTED_RELEASE_REPOSITORY=blindtechnique/keen-pbr-sb
GITHUB_API=https://api.github.com/repos
KEEN_ARCH=aarch64
KEEN_ABI=3.10
die() { printf '%s\n' "$*" >&2; exit 1; }
fetch() {
    printf '%s\n' "$1" >> "$TMP_DIR/requests"
    case "$1" in
        */releases/tags/*) cp "$FIXTURE_ASSETS/metadata" "$2" ;;
        *) cp "$FIXTURE_ASSETS/${1##*/}" "$2" ;;
    esac
}
''' + functions + '\ndownload_package\nprintf done > "$TMP_DIR/bootstrap-reached"\n'
        return self.run_shell(script, PROJECT_REPOSITORY=repository)

    def self_update(self):
        self.metadata()
        source = SELF_UPDATE.read_text(encoding="utf8")
        segment = source[source.index('if [ ! -r "$RELEASE_VERIFIER" ]'):
                         source.index('write_state installed 90')]
        script = r'''
set -eu
RELEASE_REPOSITORY=blindtechnique/keen-pbr-sb
RELEASE_API=https://api.github.com/repos/blindtechnique/keen-pbr-sb/releases/latest
RELEASE_JSON="$WORK_DIR/release.json"
INSTALLER="$WORK_DIR/install.sh"
write_state() { printf '%s\n' "$1" >> "$WORK_DIR/phases"; }
fetch_url() {
    printf '%s\n' "$2" >> "$WORK_DIR/requests"
    case "$2" in
        */releases/latest) cp "$FIXTURE_ASSETS/metadata" "$1" ;;
        *) cp "$FIXTURE_ASSETS/${2##*/}" "$1" ;;
    esac
}
''' + segment
        return self.run_shell(script)

    def test_authenticated_package_reaches_only_the_bootstrap_sentinel(self):
        result = self.download()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.work / "bootstrap-reached").exists())

    def test_changed_package_with_matching_unsigned_sums_is_not_extracted(self):
        (self.assets / PACKAGE).write_bytes(b"modified package\n")
        result = self.download()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Подпись пакета", result.stderr)
        self.assertFalse((self.work / "bootstrap-reached").exists())

    def test_missing_manifest_signature_does_not_reach_bootstrap(self):
        (self.assets / "release-manifest.sig").unlink()
        result = self.download()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.work / "bootstrap-reached").exists())

    def test_other_repository_is_rejected_before_download(self):
        result = self.download(repository="someone/another-project")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.work / "requests").exists())

    def test_authenticated_installer_runs_with_the_same_release_handoff(self):
        result = self.self_update()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.work / "executed").read_text().strip(), RELEASE)
        self.assertIn("installing", (self.work / "phases").read_text().splitlines())
        self.assertFalse(any("raw.githubusercontent.com" in url for url in
                             (self.work / "requests").read_text().splitlines()))

    def test_modified_installer_never_executes_or_starts_install_phase(self):
        with (self.assets / "install.sh").open("a", encoding="utf8") as stream:
            stream.write("# downloaded script was changed\n")
        result = self.self_update()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.work / "executed").exists())
        self.assertNotIn("installing", (self.work / "phases").read_text().splitlines())

    def test_bad_signature_never_executes_installer(self):
        (self.assets / "release-manifest.sig").write_bytes(b"0" * 384)
        result = self.self_update()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.work / "executed").exists())

    def test_embed_generator_uses_canonical_script_and_public_key_only(self):
        installer = self.root / "installer-with-test-key.sh"
        shutil.copyfile(INSTALLER, installer)
        args = [sys.executable, str(EMBEDDER), "--installer", str(installer),
                "--public-key", str(self.public_key), "--verifier", str(VERIFIER)]
        subprocess.run(args, check=True, capture_output=True, timeout=10)
        subprocess.run(args + ["--check"], check=True, capture_output=True, timeout=10)
        subprocess.run(["sh", "-n", str(installer)], check=True, capture_output=True, timeout=10)
        source = installer.read_text(encoding="utf8")
        self.assertIn(VERIFIER.read_text(encoding="utf8"), source)
        self.assertIn(self.public_key.read_text(encoding="utf8"), source)
        self.assertNotIn(self.key.read_text(encoding="utf8"), source)
        extract = shell_function(source, "prepare_release_verifier", "ensure_release_verifier")
        result = self.run_shell("set -eu\n" + extract + "\nprepare_release_verifier\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.work / "release-verify.sh").read_text(),
                         VERIFIER.read_text(encoding="utf8"))

    def test_embed_check_rejects_stale_or_missing_canonical_block(self):
        installer = self.root / "stale.sh"
        installer.write_text("#!/bin/sh\nexit 0\n", encoding="utf8")
        result = subprocess.run([sys.executable, str(EMBEDDER), "--installer", str(installer),
                                 "--public-key", str(self.public_key), "--check"],
                                capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exactly one", result.stderr)

        shutil.copyfile(INSTALLER, installer)
        args = [sys.executable, str(EMBEDDER), "--installer", str(installer),
                "--public-key", str(self.public_key), "--verifier", str(VERIFIER)]
        subprocess.run(args, check=True, capture_output=True, timeout=10)
        installer.write_bytes(installer.read_bytes().replace(b"\n", b"\r\n"))
        result = subprocess.run(args + ["--check"], capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("stale", result.stderr)

    def test_installer_authentication_precedes_rescue_extraction_and_opkg(self):
        source = INSTALLER.read_text(encoding="utf8")
        tail = source[source.index('[ "$(id -u)" = "0" ]'):]
        self.assertLess(tail.index("ensure_release_verifier\n"), tail.index("download_package\n"))
        self.assertLess(tail.index("download_package\n"), tail.index("bootstrap_rescue_helpers\n"))
        self.assertLess(tail.index("bootstrap_rescue_helpers\n"),
                        tail.index("install_package_transactionally\n"))
        makefile = (ROOT / "packages/keenetic/keen-pbr/Makefile").read_text()
        for variant in ("keen-pbr", "keen-pbr-headless"):
            package = makefile.split(f"define Package/{variant}\n", 1)[1].split("endef", 1)[0]
            install = makefile.split(f"define Package/{variant}/install\n", 1)[1].split("endef", 1)[0]
            self.assertIn("+openssl-util", package)
            self.assertIn("release-verify.sh", install)
            self.assertIn("keys/release-public.pem", install)


if __name__ == "__main__":
    unittest.main()

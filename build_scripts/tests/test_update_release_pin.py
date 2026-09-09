"""Run the real package-selection shell function without network or opkg."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "install.sh"
SELF_UPDATE = ROOT / "packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr/self-update.sh"
PACKAGE = "keen-pbr_3.3.0-test_keenetic_aarch64-3.10.ipk"
PAYLOAD = b"release pin fixture, not an installable package\n"
STABLE_RELEASE = "v3.3.0-sb.12"


def function(text: str, name: str, next_name: str) -> str:
    return text.split(f"{name}() {{", 1)[1].split(f"\n{next_name}() {{", 1)[0]


@unittest.skipUnless(shutil.which("sh"), "POSIX shell is required")
class UpdateReleasePinTest(unittest.TestCase):
    def run_download(self, requested: str, returned: str, *, pretty=False,
                     bad_hash=False, update=False, legacy_updater=False,
                     bad_signature=False):
        with tempfile.TemporaryDirectory(prefix="kpbr-release-pin-") as directory:
            root = Path(directory)
            (root / "payload").write_bytes(PAYLOAD)
            release = {
                "tag_name": returned,
                "assets": [
                    {"browser_download_url": f"https://example.invalid/{PACKAGE}"},
                    {"browser_download_url": "https://example.invalid/SHA256SUMS"},
                ],
            }
            (root / "metadata").write_text(
                json.dumps(release, indent=2 if pretty else None), encoding="utf8")
            digest = "0" * 64 if bad_hash else hashlib.sha256(PAYLOAD).hexdigest()
            (root / "sums").write_text(f"{digest}  {PACKAGE}\n", encoding="utf8")
            # This suite isolates release selection; cryptographic integration is
            # exercised separately by test_signed_update_integration.
            (root / "verifier").write_text(
                "#!/bin/sh\nexit " + ("1" if bad_signature else "0") + "\n",
                encoding="utf8")
            source = INSTALLER.read_text(encoding="utf8")
            # Run the actual argument/env initializer, not a copy of its pin
            # logic. Nothing before cleanup() performs filesystem mutations.
            initialize = source.split("\ncleanup() {", 1)[0]
            assets = "github_asset_urls() {" + function(source, "github_asset_urls", "detect_target")
            download = "download_package() {" + function(source, "download_package", "bootstrap_rescue_helpers")
            script = r'''
TMP_DIR=$FIXTURE_TMP_DIR
GITHUB_API=https://api.github.com/repos
PROJECT_REPOSITORY=blindtechnique/keen-pbr-sb
TRUSTED_RELEASE_REPOSITORY=blindtechnique/keen-pbr-sb
RELEASE_VERIFIER="$TMP_DIR/verifier"
RELEASE_PUBLIC_KEY="$TMP_DIR/key"
KEEN_ARCH=aarch64
KEEN_ABI=3.10
die() { printf '%s\n' "$*" >&2; exit 1; }
fetch() {
    printf '%s\n' "$1" >> "$TMP_DIR/requests"
    case "$1" in
        */releases/latest|*/releases/tags/*) cp "$TMP_DIR/metadata" "$2" ;;
        */SHA256SUMS) cp "$TMP_DIR/sums" "$2" ;;
        */release-manifest.tsv|*/release-manifest.sig) cp "$TMP_DIR/metadata" "$2" ;;
        *.ipk) cp "$TMP_DIR/payload" "$2" ;;
        *) die "unexpected request" ;;
    esac
}
'''
            env = {**os.environ, "FIXTURE_TMP_DIR": directory,
                   "KEEN_PBR_UPDATE_RELEASE_TAG": requested}
            shell = [shutil.which("busybox"), "sh"] if shutil.which("busybox") else ["sh"]
            program = initialize + script + assets + download + "\ndownload_package\n"
            if legacy_updater:
                # Preserve stable11's raw-tag URL and exact --update-only
                # child invocation. It does not supply the modern env handoff.
                (root / "tagged-install.sh").write_text(program, encoding="utf8")
                program = r'''
set -eu
release_tag=v3.3.0-sb.12
INSTALLER="$FIXTURE_TMP_DIR/downloaded-install.sh"
INSTALLER_URL="https://raw.githubusercontent.com/blindtechnique/keen-pbr-sb/$release_tag/install.sh"
fetch_url() {
    printf '%s\n' "$2" >> "$FIXTURE_TMP_DIR/requests"
    cp "$FIXTURE_TMP_DIR/tagged-install.sh" "$1"
}
fetch_url "$INSTALLER" "$INSTALLER_URL"
/bin/sh "$INSTALLER" --update
'''
            arguments = ["--update"] if update else []
            result = subprocess.run(
                [*shell, "-c", program, "fixture-install.sh", *arguments],
                env=env, capture_output=True, text=True, timeout=10)
            requests = root / "requests"
            return result, requests.read_text().splitlines() if requests.exists() else []

    def test_unpinned_first_install_keeps_latest_selection(self):
        result, requests = self.run_download("", "v3.3.0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(requests[0], "https://api.github.com/repos/blindtechnique/keen-pbr-sb/releases/latest")
        self.assertEqual(len(requests), 5)

    def test_update_keeps_the_tag_used_to_select_its_installer(self):
        for pretty in (False, True):
            with self.subTest(pretty=pretty):
                result, requests = self.run_download("v3.3.0-alpha.1", "v3.3.0-alpha.1", pretty=pretty)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(requests[0].endswith("/releases/tags/v3.3.0-alpha.1"))
                self.assertFalse(any(url.endswith("/latest") for url in requests))

    def test_legacy_update_without_env_handoff_uses_its_compatible_source_tag(self):
        result, requests = self.run_download("", STABLE_RELEASE, update=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(requests[0].endswith("/releases/tags/" + STABLE_RELEASE))
        self.assertFalse(any(url.endswith("/latest") for url in requests))

    def test_stable11_raw_tagged_installer_call_stays_on_that_release(self):
        result, requests = self.run_download("", STABLE_RELEASE, legacy_updater=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(requests[0],
                         f"https://raw.githubusercontent.com/blindtechnique/keen-pbr-sb/{STABLE_RELEASE}/install.sh")
        self.assertTrue(requests[1].endswith("/releases/tags/" + STABLE_RELEASE))
        self.assertFalse(any(url.endswith("/latest") for url in requests))

    def test_explicit_verified_env_tag_takes_precedence_over_legacy_default(self):
        result, requests = self.run_download("v3.3.1-sb.13", "v3.3.1-sb.13", update=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(requests[0].endswith("/releases/tags/v3.3.1-sb.13"))

    def test_legacy_default_refuses_metadata_for_a_different_release(self):
        result, requests = self.run_download("", "v3.3.1-sb.13", update=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("другой выпуск", result.stderr)
        self.assertEqual(len(requests), 1)

    def test_legacy_pin_does_not_bypass_signature_verification(self):
        result, requests = self.run_download("", STABLE_RELEASE, update=True,
                                             bad_signature=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Подпись пакета", result.stderr)
        self.assertEqual(len(requests), 5)

    def test_metadata_for_another_tag_does_not_download_a_package(self):
        result, requests = self.run_download("v3.3.0", "v3.3.1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("другой выпуск", result.stderr)
        self.assertEqual(len(requests), 1)

    def test_invalid_handoff_tag_never_becomes_a_request(self):
        for tag in ("../latest", "v1?redirect=x", "v1\nnext", "v1 space"):
            with self.subTest(tag=tag):
                result, requests = self.run_download(tag, "v3.3.0")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(requests, [])

    def test_pinning_does_not_bypass_checksum_validation(self):
        result, requests = self.run_download("v3.3.0", "v3.3.0", bad_hash=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("контрольная сумма", result.stderr)
        self.assertEqual(len(requests), 3)

    def test_handoff_is_consumed_before_postinst_can_inherit_it(self):
        source = INSTALLER.read_text(encoding="utf8")
        consume = "REQUESTED_RELEASE_TAG=${KEEN_PBR_UPDATE_RELEASE_TAG:-}"
        clear = "unset KEEN_PBR_UPDATE_RELEASE_TAG"
        self.assertLess(source.index(consume), source.index(clear))
        self.assertLess(source.index(clear), source.index("download_package()"))
        update = SELF_UPDATE.read_text(encoding="utf8")
        self.assertIn('KEEN_PBR_UPDATE_RELEASE_TAG="$release_tag" \\\n', update)
        self.assertIn('KEEN_PBR_UPDATE_LOCK_TRANSFER=1 /bin/sh "$INSTALLER" --update', update)


if __name__ == "__main__":
    unittest.main()

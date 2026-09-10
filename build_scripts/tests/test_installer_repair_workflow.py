"""Bounded wiring checks for installer-only repair; no GitHub writes or keys."""

from pathlib import Path
import re
import shlex
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/repair-keenetic-installer.yml"


class InstallerRepairWorkflowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_only_trusted_main_manual_dispatch_can_sign(self):
        triggers = self.workflow.split("permissions:", 1)[0]
        self.assertIn("  workflow_dispatch:", triggers)
        self.assertNotRegex(triggers, r"(?m)^  (push|pull_request|workflow_run):")
        self.assertIn("github.repository == 'blindtechnique/keen-pbr-sb'", self.workflow)
        self.assertIn("github.ref == 'refs/heads/main'", self.workflow)
        self.assertIn("ref: ${{ github.sha }}", self.workflow)
        self.assertIn("persist-credentials: false", self.workflow)
        self.assertIn("cancel-in-progress: false", self.workflow)

    def test_inputs_are_data_and_existing_snapshot_is_pinned_twice(self):
        self.assertIn("EXPECTED_MANIFEST_SHA256: ${{ inputs.expected_manifest_sha256 }}", self.workflow)
        self.assertIn('[[ "$EXPECTED_MANIFEST_SHA256" =~ ^[0-9a-f]{64}$ ]]', self.workflow)
        self.assertEqual(self.workflow.count('"$EXPECTED_MANIFEST_SHA256" repair/'), 2)
        for line in self.workflow.splitlines():
            if "${{ inputs." in line:
                self.assertTrue(line.strip().startswith((
                    "group:", "RELEASE_TAG:", "EXPECTED_MANIFEST_SHA256:"
                )), line)

    def test_original_signature_all_profiles_and_package_source_are_verified(self):
        self.assertIn('stable "$RELEASE_TAG" installer any any install.sh repair/original/install.sh', self.workflow)
        self.assertIn('test "${#packages[@]}" -eq 3', self.workflow)
        self.assertIn("for profile in aarch64-3.10 mips-3.4 mipsel-3.4; do", self.workflow)
        self.assertIn('stable "$RELEASE_TAG" package "${profile%%-*}" "${profile#*-}"', self.workflow)
        self.assertIn('--expected-commit "${PACKAGE_SOURCE:0:12}"', self.workflow)
        self.assertIn("cmp repair/original/SHA256SUMS repair/expected-SHA256SUMS", self.workflow)

    def test_installer_only_tag_repair_does_not_replace_package_provenance(self):
        source = 'PACKAGE_SOURCE=$(awk -F \'\\t\' \'$1 == "source" {print $2}\' repair/original/release-manifest.tsv)'
        self.assertIn(source, self.workflow)
        verified = 'stable "$RELEASE_TAG" installer any any install.sh repair/original/install.sh'
        self.assertLess(self.workflow.index(verified), self.workflow.index(source))
        self.assertNotIn("FETCH_HEAD", self.workflow)
        self.assertEqual(len(re.findall(r"(?m)^\s*PACKAGE_SOURCE=", self.workflow)), 1)
        self.assertIn("cmp repair/tag-before repair/tag-current", self.workflow)
        self.assertIn("cmp repair/tag-before repair/tag-after", self.workflow)
        self.assertNotIn("package/tag", self.workflow)

    def test_mixed_source_provenance_does_not_relabel_packages(self):
        signer = next(line for line in self.workflow.splitlines()
                      if "python3 build_scripts/sign-keenetic-release.py " in line)
        self.assertIn('--source "$PACKAGE_SOURCE"', signer)
        self.assertIn('--build "installer-${INSTALLER_SHA}-github-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"', signer)
        self.assertNotIn('--source "$INSTALLER_SHA"', signer)
        self.assertIn('grep -Fx "STABLE_RELEASE_TAG=\'$RELEASE_TAG\'" install.sh', self.workflow)
        self.assertIn("cmp repair/original-package-manifest repair/candidate-package-manifest", self.workflow)
        self.assertIn("sha256sum -c ../original/SHA256SUMS", self.workflow)

    def test_only_three_named_assets_can_be_uploaded(self):
        uploads = [line.strip() for line in self.workflow.splitlines()
                   if line.strip().startswith("gh release upload ")]
        self.assertEqual(len(uploads), 1)
        self.assertEqual(shlex.split(uploads[0]), [
            "gh", "release", "upload", "$RELEASE_TAG", "--repo", "$GITHUB_REPOSITORY",
            "--clobber", "repair/candidate/install.sh",
            "repair/candidate/release-manifest.tsv", "repair/candidate/release-manifest.sig",
        ])
        self.assertNotRegex(self.workflow, r"gh release (create|edit|delete)\b")
        self.assertNotRegex(self.workflow, r"git (push|tag)\b")
        self.assertNotRegex(self.workflow, r"(?m)^\s+(?:make|cmake|docker|opkg)\s")

    def test_release_tag_latest_and_other_assets_stay_unchanged(self):
        self.assertIn(".prerelease == true and .draft == false and .immutable != true", self.workflow)
        upload_at = self.workflow.index("gh release upload ")
        for before in ("cmp repair/identity-before repair/identity-current",
                       "cmp repair/tag-before repair/tag-current",
                       "cmp repair/latest-before repair/latest-current"):
            self.assertLess(self.workflow.index(before), upload_at)
        for after in ("cmp repair/unchanged-before repair/unchanged-after",
                      "cmp repair/tag-before repair/tag-after",
                      "cmp repair/latest-before repair/latest-after",
                      "cmp repair/original/SHA256SUMS repair/published/SHA256SUMS"):
            self.assertGreater(self.workflow.index(after), upload_at)

    def test_focused_gates_precede_signing_and_secret_stays_step_scoped(self):
        gate_at = self.workflow.index("python3 -m unittest ")
        sign_at = self.workflow.index("python3 build_scripts/sign-keenetic-release.py ")
        self.assertLess(gate_at, sign_at)
        for test in ("test_installer_repair_workflow", "test_signed_update_integration",
                     "test_keenetic_release_signatures"):
            self.assertIn("build_scripts.tests." + test, self.workflow)
        self.assertIn("busybox sh -n install.sh", self.workflow)
        self.assertIn("--public-key packages/keys/keenetic-release-public.pem --check", self.workflow)
        self.assertEqual(self.workflow.count("${{ secrets.KEENETIC_RELEASE_SIGNING_KEY }}"), 1)
        secret_line = next(line for line in self.workflow.splitlines()
                           if "${{ secrets.KEENETIC_RELEASE_SIGNING_KEY }}" in line)
        self.assertTrue(secret_line.startswith("          "))
        self.assertIn("trap 'rm -f -- \"$signing_key\"' EXIT", self.workflow)
        self.assertIn("unset KEENETIC_RELEASE_SIGNING_KEY", self.workflow)
        self.assertNotIn("set -x", self.workflow)
        self.assertIn("name: installer-before-repair", self.workflow)


if __name__ == "__main__":
    unittest.main()

"""Keep every release job on one frozen source and verify before publishing.

This is a narrow wiring check, not a YAML parser or an Actions runner. It reads
the workflow's existing indentation structure using only the Python stdlib;
the resolver's Git/event semantics are tested separately with temporary repos.
"""

from __future__ import annotations

import re
import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/release-keenetic.yml"
SOURCE = "needs.resolve-source.outputs."
TRUSTED_PUBLISHER = "github.repository == 'blindtechnique/keen-pbr-sb' && github.event_name != 'pull_request' && "
SIGNING_JOBS = {
    "publish-release": "Sign release manifest and installer",
    "upload-alpha-artifact": "Sign alpha manifest and installer",
    "upload-next-artifact": "Sign next manifest and installer",
}


def blocks(text: str, pattern: str) -> dict[str, str]:
    matches = list(re.finditer(pattern, text, re.MULTILINE))
    result: dict[str, str] = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        name = match.group(1)
        if name in result:
            raise AssertionError(f"duplicate workflow block: {name}")
        result[name] = text[match.start():end]
    return result


def field(block: str, name: str, indent: int) -> tuple[str, str]:
    match = re.search(rf"^{' ' * indent}{re.escape(name)}:[ \t]*(.*)$", block, re.MULTILINE)
    if match is None:
        raise AssertionError(f"missing workflow field at indent {indent}: {name}")
    end = len(block)
    for candidate in re.finditer(r"^([ ]*)(\S.*)$", block[match.end():], re.MULTILINE):
        if len(candidate.group(1)) <= indent and not candidate.group(2).startswith("#"):
            end = match.end() + candidate.start()
            break
    return match.group(1).strip(), block[match.end():end]


def expression(value: str) -> str:
    value = value.strip()
    if value.startswith("${{") and value.endswith("}}"):
        value = value[3:-2].strip()
    return value


def steps(job: str) -> dict[str, str]:
    return blocks(job, r"^      - name:[ \t]*(.+)$")


def shell(step: str) -> str:
    _, body = field(step, "run", 8)
    return "\n".join(
        line for line in body.replace("\\\n", " ").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )


class ReleaseWorkflowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WORKFLOW.read_text(encoding="utf-8")
        _, job_text = cls.text.split("\njobs:\n", 1)
        cls.jobs = blocks(job_text, r"^  ([A-Za-z0-9_-]+):[ \t]*$")

    def test_resolver_exports_the_single_effective_release_contract(self) -> None:
        self.assertIn("resolve-source", self.jobs)
        _, outputs = field(self.jobs["resolve-source"], "outputs", 4)
        for name in ("source_sha", "release_tag", "release", "channel", "build_matrix"):
            with self.subTest(output=name):
                value, _ = field(outputs, name, 6)
                self.assertRegex(expression(value), rf"^steps\.[\w-]+\.outputs\.{name}$")
        # For PRs the event SHA is the integration/merge commit. Replacing it
        # with the contributor's head would silently stop testing that merge.
        self.assertNotIn("github.event.pull_request.head.sha", self.text)

    def test_every_consumer_depends_on_the_resolver_and_pins_checkout(self) -> None:
        required_jobs = {
            "frontend", "backend", "crash-diagnostics-smoke", "clang-thread-safety",
            "firewall-integration", "transport-manager", "build", "publish-release",
            "upload-alpha-artifact", "upload-next-artifact",
        }
        self.assertTrue(required_jobs <= self.jobs.keys())
        for name, job in self.jobs.items():
            if name == "resolve-source":
                continue
            with self.subTest(job=name):
                inline, following = field(job, "needs", 4)
                needs = set(re.findall(r"[A-Za-z][A-Za-z0-9_-]*", inline + "\n" + following))
                self.assertIn("resolve-source", needs)
                checkouts = [step for step in steps(job).values() if "uses: actions/checkout@" in step]
                if name in required_jobs:
                    self.assertTrue(checkouts, f"{name} has no source checkout")
                self.assertEqual(len(checkouts), job.count("uses: actions/checkout@"))
                for checkout in checkouts:
                    _, checkout_inputs = field(checkout, "with", 8)
                    ref, _ = field(checkout_inputs, "ref", 10)
                    if "name: Checkout reviewed release signing tools" in checkout:
                        self.assertIn(name, SIGNING_JOBS)
                        self.assertEqual(expression(ref), "github.sha")
                        path, _ = field(checkout_inputs, "path", 10)
                        self.assertEqual(path, ".release-signing-tools")
                        credentials, _ = field(checkout_inputs, "persist-credentials", 10)
                        self.assertEqual(credentials, "false")
                    else:
                        self.assertEqual(expression(ref), SOURCE + "source_sha")

    def test_matrix_and_destinations_use_resolved_intent_not_dispatch_branch(self) -> None:
        _, strategy = field(self.jobs["build"], "strategy", 4)
        matrix, _ = field(strategy, "matrix", 6)
        self.assertEqual(expression(matrix), f"fromJSON({SOURCE}build_matrix)")
        publish_if, _ = field(self.jobs["publish-release"], "if", 4)
        self.assertEqual(expression(publish_if), TRUSTED_PUBLISHER + SOURCE + "release == 'true'")
        for channel in ("alpha", "next"):
            with self.subTest(channel=channel):
                condition, _ = field(self.jobs[f"upload-{channel}-artifact"], "if", 4)
                self.assertEqual(expression(condition), TRUSTED_PUBLISHER + SOURCE + f"channel == '{channel}'")
        # Manual release-tag rebuilds run on their selected source, not on the
        # dispatch UI's alpha/next branch. Resolver tests cover channel=none and
        # the full architecture matrix for those releases.

    def test_publisher_uses_frozen_tag_and_commit(self) -> None:
        publish = self.jobs["publish-release"]
        _, environment = field(publish, "env", 4)
        for variable, output in (("SOURCE_SHA", "source_sha"), ("RELEASE_TAG", "release_tag")):
            with self.subTest(variable=variable):
                value, _ = field(environment, variable, 6)
                self.assertEqual(expression(value), SOURCE + output)
        publish_step = steps(publish)["Create or update GitHub Release"]
        _, publish_inputs = field(publish_step, "with", 8)
        target, _ = field(publish_inputs, "target_commitish", 10)
        self.assertEqual(expression(target), SOURCE + "source_sha")

    def assert_fresh_tag_check(self, code: str) -> None:
        fetch = re.search(r"\bgit fetch[^\n]*refs/tags/\$\{?RELEASE_TAG\}?", code)
        self.assertIsNotNone(fetch, "tag must be fetched freshly, not read from checkout's cached tag")
        peeled = re.search(r"\bgit rev-parse[^\n]*FETCH_HEAD\^\{commit\}", code)
        self.assertIsNotNone(peeled, "annotated tag must be peeled to its commit")
        comparisons = [
            line for line in code.splitlines()
            if "SOURCE_SHA" in line and re.search(r"\s(?:=|!=)\s", line)
        ]
        self.assertTrue(comparisons, "fresh tag commit must be compared with frozen SOURCE_SHA")
        self.assertLess(fetch.start(), peeled.start())

    def test_all_artifacts_and_tag_are_checked_before_any_release_asset_mutation(self) -> None:
        release_steps = steps(self.jobs["publish-release"])
        names = list(release_steps)
        verify_name = "Verify release tag and all IPKs"
        self.assertIn(verify_name, release_steps)
        verify = shell(release_steps[verify_name])
        self.assert_fresh_tag_check(verify)
        self.assertIn("validate-keenetic-ipk.py", verify)
        self.assertIn('--expected-commit "$EXPECTED_COMMIT"', verify)
        self.assertRegex(verify, r"EXPECTED_COMMIT=.+git rev-parse[^\n]*--short=12[^\n]*\$\{?SOURCE_SHA\}?")
        for config in ("aarch64-3.10", "mips-3.4", "mipsel-3.4"):
            self.assertIn(config, verify)
        self.assertIn("--arch", verify)
        self.assertRegex(verify, r"-eq\s+3\b", "release must contain all three full-package artifacts")
        mutation_steps = [
            name for name, step in release_steps.items()
            if "gh release delete-asset" in step or "uses: softprops/action-gh-release@" in step
        ]
        self.assertEqual(len(mutation_steps), 2)
        for name in mutation_steps:
            with self.subTest(mutation=name):
                self.assertLess(names.index(verify_name), names.index(name))
                self.assertNotRegex(release_steps[name], r"continue-on-error:\s*true")
        delete_steps = [step for step in release_steps.values() if "gh release delete-asset" in step]
        self.assertEqual(len(delete_steps), 1)
        before_delete = shell(delete_steps[0]).split("gh release delete-asset", 1)[0]
        self.assert_fresh_tag_check(before_delete)
        self.assertNotRegex(release_steps[verify_name], r"continue-on-error:\s*true")

    def test_contract_is_run_before_consumers_check_out_an_older_tag(self) -> None:
        # A manually selected old tag need not contain these new test files.
        # Run the workflow wiring gate on the event/workflow checkout first.
        self.assertIn("build_scripts.tests.test_release_workflow", self.jobs["resolve-source"])
        self.assertIn("build_scripts.tests.test_keenetic_release_signatures", self.jobs["resolve-source"])

    def test_signer_secret_is_step_scoped_and_unavailable_to_pr_jobs(self) -> None:
        references = "${{ secrets.KEENETIC_RELEASE_SIGNING_KEY }}"
        self.assertEqual(self.text.count(references), len(SIGNING_JOBS))
        for name, job in self.jobs.items():
            with self.subTest(job=name):
                if name not in SIGNING_JOBS:
                    self.assertNotIn("KEENETIC_RELEASE_SIGNING_KEY", job)
                    continue
                step = steps(job)[SIGNING_JOBS[name]]
                _, environment = field(step, "env", 8)
                value, _ = field(environment, "KEENETIC_RELEASE_SIGNING_KEY", 10)
                self.assertEqual(value, references)
                self.assertNotIn(references, job.replace(step, ""))
                condition, _ = field(job, "if", 4)
                self.assertTrue(expression(condition).startswith(TRUSTED_PUBLISHER))
                self.assertNotRegex(step, r"continue-on-error:\s*true")

    def test_signatures_cover_frozen_installer_before_any_publication(self) -> None:
        for name, sign_name in SIGNING_JOBS.items():
            with self.subTest(job=name):
                job_steps = steps(self.jobs[name])
                names = list(job_steps)
                code = shell(job_steps[sign_name])
                self.assertIn('umask 077', code)
                self.assertIn('mktemp "$RUNNER_TEMP/keenetic-release-key.XXXXXX"', code)
                self.assertIn('trap \'rm -f -- "$signing_key"\' EXIT', code)
                self.assertLess(code.index('unset KEENETIC_RELEASE_SIGNING_KEY'), code.index('python3 '))
                self.assertIn('.release-signing-tools/build_scripts/embed-release-verifier.py', code)
                self.assertIn('--installer install.sh', code)
                self.assertIn('--check', code)
                self.assertIn('--source "$SOURCE_SHA"', code)
                self.assertIn('--public-key .release-signing-tools/packages/keys/keenetic-release-public.pem', code)
                self.assertLess(code.index('embed-release-verifier.py'), code.index('sign-keenetic-release.py'))
                self.assertIn('--key "$signing_key"', code)
                channel = {'publish-release': 'stable', 'upload-alpha-artifact': 'alpha', 'upload-next-artifact': 'next'}[name]
                self.assertIn('--channel ' + channel, code)
                if channel == 'stable':
                    self.assertIn('--release "$RELEASE_TAG"', code)
                else:
                    self.assertIn(f'--release "{channel}-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"', code)
                for step_name, step in job_steps.items():
                    if 'gh release delete-asset' in step or 'uses: softprops/action-gh-release@' in step or 'uses: actions/upload-artifact@' in step:
                        self.assertLess(names.index(sign_name), names.index(step_name))
                        if 'gh release delete-asset' not in step:
                            for artifact in ('install.sh', 'release-manifest.tsv', 'release-manifest.sig', 'SHA256SUMS'):
                                self.assertIn('release-assets/' + artifact, step)

    @unittest.skipUnless(shutil.which('bash'), 'workflow shell validation requires bash')
    def test_signing_steps_have_valid_runner_shell_syntax(self) -> None:
        for name, sign_name in SIGNING_JOBS.items():
            with self.subTest(job=name):
                _, body = field(steps(self.jobs[name])[sign_name], 'run', 8)
                result = subprocess.run(['bash', '-n'], input=textwrap.dedent(body), text=True, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which('bash') and shutil.which('python3'), 'runner fixture requires bash and python3')
    def test_signing_secret_cleanup_and_failures_before_publish(self) -> None:
        # Execute the actual stable step with test-only data and fake reviewed
        # helpers: no real key, GitHub, opkg, network or package build involved.
        _, body = field(steps(self.jobs['publish-release'])[SIGNING_JOBS['publish-release']], 'run', 8)
        code = textwrap.dedent(body)
        for scenario in ('success', 'missing-secret', 'old-installer', 'signer-failure'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                scripts = root / '.release-signing-tools/build_scripts'
                scripts.mkdir(parents=True)
                runner_temp = root / 'runner-temp'
                runner_temp.mkdir()
                (scripts / 'embed-release-verifier.py').write_text(
                    'import os, sys\n'
                    'assert "KEENETIC_RELEASE_SIGNING_KEY" not in os.environ\n'
                    'sys.exit(1 if os.environ["FIXTURE_SCENARIO"] == "old-installer" else 0)\n', encoding='utf-8')
                (scripts / 'sign-keenetic-release.py').write_text(
                    'import os, stat, sys\nfrom pathlib import Path\n'
                    'assert "KEENETIC_RELEASE_SIGNING_KEY" not in os.environ\n'
                    'key = Path(sys.argv[sys.argv.index("--key") + 1])\n'
                    'assert key.read_text().strip() == "TEST-ONLY CI secret fixture"\n'
                    'assert stat.S_IMODE(key.stat().st_mode) == 0o600\n'
                    'Path("signer-started").touch()\n'
                    'sys.exit(1 if os.environ["FIXTURE_SCENARIO"] == "signer-failure" else 0)\n', encoding='utf-8')
                environment = dict(os.environ)
                environment.update({
                    'RUNNER_TEMP': str(runner_temp), 'GITHUB_RUN_ID': '123',
                    'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_REPOSITORY': 'blindtechnique/keen-pbr-sb',
                    'RELEASE_TAG': 'v3.3.1', 'SOURCE_SHA': 'a' * 40,
                    'FIXTURE_SCENARIO': scenario,
                    'KEENETIC_RELEASE_SIGNING_KEY': '' if scenario == 'missing-secret' else 'TEST-ONLY CI secret fixture',
                })
                result = subprocess.run(['bash', '-c', code], cwd=root, env=environment, text=True, capture_output=True, timeout=15)
                self.assertEqual(result.returncode == 0, scenario == 'success', result.stderr)
                self.assertEqual(list(runner_temp.iterdir()), [], 'temporary signing key must be removed on both success and failure')
                self.assertEqual((root / 'signer-started').exists(), scenario in ('success', 'signer-failure'))
                self.assertNotIn('TEST-ONLY CI secret fixture', result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()

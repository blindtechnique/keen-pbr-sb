"""Keep every release job on one frozen source and verify before publishing.

This is a narrow wiring check, not a YAML parser or an Actions runner. It reads
the workflow's existing indentation structure using only the Python stdlib;
the resolver's Git/event semantics are tested separately with temporary repos.
"""

from __future__ import annotations

import re
import os
import json
import shlex
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/release-keenetic.yml"
CI_DEPENDENCIES = ROOT / "build_scripts/ci-install-ubuntu-deps.sh"
SOURCE = "needs.resolve-source.outputs."
TRUSTED_PUBLISHER = "github.repository == 'blindtechnique/keen-pbr-sb' && github.event_name != 'pull_request' && "
SIGNING_JOBS = {
    "publish-release": "Sign release manifest and installer",
    "upload-stable-candidate-artifact": "Sign stable candidate manifest and installer",
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
        for name in ("source_sha", "release_tag", "release", "candidate", "channel", "build_matrix"):
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
            "upload-alpha-artifact", "upload-next-artifact", "upload-stable-candidate-artifact",
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
        condition, _ = field(self.jobs["upload-stable-candidate-artifact"], "if", 4)
        self.assertEqual(expression(condition), TRUSTED_PUBLISHER + SOURCE + "candidate == 'true'")
        # Manual release-tag rebuilds run on their selected source, not on the
        # dispatch UI's alpha/next branch. Resolver tests cover channel=stable and
        # the full architecture matrix for those releases.

    def test_native_dependency_steps_use_only_ubuntu_without_changing_packages(self) -> None:
        common = ['libcurl4-openssl-dev', 'libnl-3-dev', 'libnl-route-3-dev', 'libunwind-dev']
        tail = ['pkg-config', 'zlib1g-dev']
        expected = {
            'backend': common + ['busybox-static', 'lua5.3'] + tail,
            'crash-diagnostics-smoke': common + tail,
            'clang-thread-safety': ['clang'] + common + tail,
        }
        for name, packages in expected.items():
            with self.subTest(job=name):
                step_name = 'Install Clang build dependencies' if name == 'clang-thread-safety' else 'Install native build dependencies'
                code = shell(steps(self.jobs[name])[step_name])
                self.assertEqual(shlex.split(code), ['sh', 'build_scripts/ci-install-ubuntu-deps.sh', *packages])
        helper = CI_DEPENDENCIES.read_text(encoding='utf-8')
        for forbidden in ('--allow-unauthenticated', 'AllowInsecure', 'Verify-Peer', '|| true', 'rm ', 'mv '):
            self.assertNotIn(forbidden, helper)

    def run_fake_ci_dependencies(self, packages: list[str], *, update_status: int = 0, install_status: int = 0) -> tuple[subprocess.CompletedProcess[str], list[list[str]]]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            calls = root / 'apt-calls.jsonl'
            sudo = root / 'sudo'
            sudo.write_text('#!/bin/sh\n[ "$1" = apt-get ] || exit 97\nexec "$@"\n', encoding='utf-8')
            sudo.chmod(0o755)
            apt = root / 'apt-get'
            apt.write_text(
                '#!/usr/bin/env python3\nimport json, os, sys\n'
                'with open(os.environ["FIXTURE_APT_CALLS"], "a") as out:\n'
                '    out.write(json.dumps(sys.argv[1:]) + "\\n")\n'
                'kind = "UPDATE" if sys.argv[-1] == "update" else "INSTALL"\n'
                'sys.exit(int(os.environ["FIXTURE_APT_" + kind + "_STATUS"]))\n', encoding='utf-8')
            apt.chmod(0o755)
            environment = dict(os.environ)
            environment.update({
                'PATH': str(root) + os.pathsep + environment.get('PATH', ''),
                'FIXTURE_APT_CALLS': str(calls),
                'FIXTURE_APT_UPDATE_STATUS': str(update_status),
                'FIXTURE_APT_INSTALL_STATUS': str(install_status),
            })
            result = subprocess.run(['sh', str(CI_DEPENDENCIES), *packages], cwd=root, env=environment, text=True, capture_output=True, timeout=10)
            commands = [json.loads(line) for line in calls.read_text().splitlines()] if calls.exists() else []
            return result, commands

    @unittest.skipUnless(shutil.which('sh') and shutil.which('python3'), 'dependency fixture requires sh and python3')
    def test_ci_dependencies_forward_unchanged_args_and_same_apt_source_options(self) -> None:
        packages = ['libcurl4-openssl-dev', 'clang=1:18.0-1', 'argument with spaces']
        result, commands = self.run_fake_ci_dependencies(packages)
        self.assertEqual(result.returncode, 0, result.stderr)
        options = ['-o', 'Dir::Etc::sourcelist=/etc/apt/sources.list.d/ubuntu.sources', '-o', 'Dir::Etc::sourceparts=/dev/null']
        self.assertEqual(commands, [options + ['update'], options + ['install', '-y', *packages]])

    @unittest.skipUnless(shutil.which('sh') and shutil.which('python3'), 'dependency fixture requires sh and python3')
    def test_ci_dependencies_failed_update_never_installs(self) -> None:
        result, commands = self.run_fake_ci_dependencies(['clang'], update_status=100)
        self.assertEqual(result.returncode, 100)
        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0][-1], 'update')

    @unittest.skipUnless(shutil.which('sh') and shutil.which('python3'), 'dependency fixture requires sh and python3')
    def test_ci_dependencies_propagate_install_failure(self) -> None:
        result, commands = self.run_fake_ci_dependencies(['clang'], install_status=42)
        self.assertEqual(result.returncode, 42)
        self.assertEqual(len(commands), 2)
        self.assertEqual(commands[1][-3:], ['install', '-y', 'clang'])

    @unittest.skipUnless(shutil.which('sh') and shutil.which('python3'), 'dependency fixture requires sh and python3')
    def test_ci_dependencies_empty_request_does_not_call_apt(self) -> None:
        result, commands = self.run_fake_ci_dependencies([])
        self.assertEqual(result.returncode, 2)
        self.assertEqual(commands, [])

    def test_publisher_uses_frozen_tag_and_commit(self) -> None:
        publish = self.jobs["publish-release"]
        _, environment = field(publish, "env", 4)
        for variable, output in (("SOURCE_SHA", "source_sha"), ("RELEASE_TAG", "release_tag")):
            with self.subTest(variable=variable):
                value, _ = field(environment, variable, 6)
                self.assertEqual(expression(value), SOURCE + output)
        publish_code = shell(steps(publish)["Create GitHub Pre-release"])
        self.assertIn('gh release create "$RELEASE_TAG"', publish_code)
        self.assertIn('--target "$SOURCE_SHA" --verify-tag --prerelease --latest=false', publish_code)
        self.assertIn('--title "keen-pbr-sb $RELEASE_TAG — Beta"', publish_code)

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
            if "gh release create" in step
        ]
        self.assertEqual(len(mutation_steps), 1)
        for name in mutation_steps:
            with self.subTest(mutation=name):
                self.assertLess(names.index(verify_name), names.index(name))
                self.assertNotRegex(release_steps[name], r"continue-on-error:\s*true")
        before_create = shell(release_steps[mutation_steps[0]]).split("gh release create", 1)[0]
        self.assert_fresh_tag_check(before_create)
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
                channel = {'publish-release': 'stable', 'upload-stable-candidate-artifact': 'stable', 'upload-alpha-artifact': 'alpha', 'upload-next-artifact': 'next'}[name]
                self.assertIn('--channel ' + channel, code)
                if channel == 'stable':
                    self.assertIn('--release "$RELEASE_TAG"', code)
                else:
                    self.assertIn(f'--release "{channel}-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"', code)
                for step_name, step in job_steps.items():
                    if 'gh release delete-asset' in step or 'gh release create' in step or 'uses: softprops/action-gh-release@' in step or 'uses: actions/upload-artifact@' in step:
                        self.assertLess(names.index(sign_name), names.index(step_name))
                        if 'gh release delete-asset' not in step:
                            for artifact in ('install.sh', 'release-manifest.tsv', 'release-manifest.sig', 'SHA256SUMS'):
                                self.assertIn('release-assets/' + artifact, step)

    def test_main_candidate_requires_all_profiles_and_gates_without_promoting_stable(self) -> None:
        job = self.jobs['upload-stable-candidate-artifact']
        _, environment = field(job, 'env', 4)
        for variable, output in (('SOURCE_SHA', 'source_sha'), ('RELEASE_TAG', 'release_tag')):
            value, _ = field(environment, variable, 6)
            self.assertEqual(expression(value), SOURCE + output)
        _, permissions = field(job, 'permissions', 4)
        contents, _ = field(permissions, 'contents', 6)
        self.assertEqual(contents, 'write')
        inline, following = field(job, 'needs', 4)
        for gate in ('build', 'backend', 'crash-diagnostics-smoke', 'clang-thread-safety', 'firewall-integration'):
            self.assertIn(gate, inline + following)
        # The build already depends on both the frontend and Go gates.
        inline, following = field(self.jobs['build'], 'needs', 4)
        for gate in ('frontend', 'transport-manager'):
            self.assertIn(gate, inline + following)
        job_steps = steps(job)
        verify = shell(job_steps['Verify all candidate IPKs and create checksums'])
        for config in ('aarch64-3.10', 'mips-3.4', 'mipsel-3.4'):
            self.assertIn(config, verify)
        self.assertIn('-eq 3', verify)
        self.assertIn('--expected-commit "$EXPECTED_COMMIT"', verify)
        self.assertIn('--arch "${config%%-*}"', verify)
        names = list(job_steps)
        self.assertLess(names.index('Verify all candidate IPKs and create checksums'), names.index(SIGNING_JOBS['upload-stable-candidate-artifact']))
        upload = job_steps['Upload stable candidate workflow artifact']
        self.assertIn('name: keen-pbr-stable-candidate-ipk', upload)
        publish = shell(job_steps['Publish new Beta Pre-release'])
        self.assertLess(names.index('Upload stable candidate workflow artifact'), names.index('Publish new Beta Pre-release'))
        self.assertIn('gh release create "$RELEASE_TAG"', publish)
        self.assertIn('--target "$SOURCE_SHA" --prerelease --latest=false', publish)
        self.assertIn('git ls-remote --exit-code --tags origin "refs/tags/$RELEASE_TAG"', publish)
        self.assertIn('push a new commit to main for a new timestamped release', publish)
        self.assertNotIn('advance KEEN_PBR_RELEASE', publish)
        self.assertIn('"$tag_status" -ne 2', publish)
        self.assertNotIn('softprops/action-gh-release', job)
        self.assertNotIn('make_latest:', job)
        self.assertNotIn('--channel beta', job)
        self.assertNotIn('beta-$GITHUB_RUN_ID', job)
        self.assertNotIn('delete-asset', job)
        self.assertNotIn('continue-on-error', job)
        trigger_text = self.text.split('\njobs:', 1)[0]
        self.assertEqual(trigger_text.count('      - main\n'), 2)
        self.assertNotIn('      - beta\n', trigger_text)

    @unittest.skipUnless(shutil.which('bash'), 'publication fixtures require bash')
    def test_publishers_never_replace_existing_release_assets_or_promote_on_rerun(self) -> None:
        for name, job in self.jobs.items():
            if 'gh release' in job or 'uses: softprops/action-gh-release@' in job:
                self.assertIn(name, ('publish-release', 'upload-stable-candidate-artifact'))
                condition, _ = field(job, 'if', 4)
                intent = 'release' if name == 'publish-release' else 'candidate'
                self.assertEqual(expression(condition), TRUSTED_PUBLISHER + SOURCE + f"{intent} == 'true'")
                for forbidden in ('delete-asset', 'gh release edit', 'gh release upload', 'git push', '--force', 'softprops/action-gh-release'):
                    self.assertNotIn(forbidden, job)
                self.assertIn('--prerelease --latest=false', job)
        _, body = field(steps(self.jobs['upload-stable-candidate-artifact'])['Publish new Beta Pre-release'], 'run', 8)
        code = textwrap.dedent(body)
        fake_commands = '''
git() {
  case "$1" in
    rev-parse) printf '%s\\n' "$SOURCE_SHA" ;;
    ls-remote) return "$FIXTURE_TAG_STATUS" ;;
    *) return 99 ;;
  esac
}
gh() {
  printf '%s\\n' "$*" >> "$FIXTURE_CALLS"
  return 0
}
'''
        for scenario, tag_status, expected_exit, should_create in (
            ('new tag', 2, 0, True),
            ('new tag with release notes', 2, 0, True),
            ('new tag without matching notes', 2, 0, True),
            ('existing tag and release', 0, 0, False),
            ('existing timestamp tag and release', 0, 0, False),
            ('remote failure', 128, 128, False),
        ):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                calls = root / 'github-calls'
                if scenario == 'new tag with release notes':
                    (root / 'CHANGELOG.md').write_text(
                        '# Changelog\n\n## [3x3x0-sbx12]\nWrong regex match.\n'
                        '## [3.3.0-sb.12] — Beta\n\nShort release summary.\n'
                        '### Added\n- New release feature.\n\n'
                        '## [3.3.0]\nDetailed implementation history.\n', encoding='utf-8')
                elif scenario == 'new tag without matching notes':
                    (root / 'CHANGELOG.md').write_text(
                        '# Changelog\n\n## [3.3.0]\nDetailed implementation history.\n', encoding='utf-8')
                release_tag = 'v3.3.2-20260910120000' if scenario == 'existing timestamp tag and release' else 'v3.3.0-sb.12'
                environment = dict(os.environ)
                environment.update({
                    'SOURCE_SHA': 'a' * 40, 'RELEASE_TAG': release_tag,
                    'GITHUB_REPOSITORY': 'blindtechnique/keen-pbr-sb',
                    'FIXTURE_TAG_STATUS': str(tag_status), 'FIXTURE_CALLS': str(calls),
                })
                result = subprocess.run(['bash', '-c', fake_commands + code], cwd=root, env=environment, text=True, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, expected_exit, result.stderr)
                self.assertEqual(calls.exists(), should_create)
                if should_create:
                    command = calls.read_text(encoding='utf-8')
                    self.assertIn('release create v3.3.0-sb.12', command)
                    self.assertIn('--target ' + 'a' * 40, command)
                    self.assertIn('--prerelease --latest=false', command)
                    self.assertIn('--notes-file BETA_NOTES.md', command)
                    notes = (root / 'BETA_NOTES.md').read_text(encoding='utf-8')
                    if scenario == 'new tag with release notes':
                        self.assertIn('Short release summary.', notes)
                        self.assertIn('### Added\n- New release feature.', notes)
                        self.assertNotIn('Wrong regex match.', notes)
                        self.assertNotIn('Detailed implementation history.', notes)
                        self.assertNotIn('Beta build from', notes)
                    else:
                        self.assertIn('Beta build from', notes)
                        self.assertIn('aarch64-3.10, mips-3.4, mipsel-3.4', notes)
                if tag_status == 0:
                    self.assertIn('already exists and was not changed', result.stdout)
                    self.assertIn('push a new commit to main for a new timestamped release', result.stdout)

    @unittest.skipUnless(shutil.which('bash') and shutil.which('awk'), 'release notes fixtures require bash and awk')
    def test_both_publishers_extract_exact_notes_with_timestamp_only_base_fallback(self) -> None:
        # Execute the real workflow snippets with local stubs: no GitHub,
        # network, signing secret, package build, or release mutation involved.
        cases = (
            ('timestamp base fallback', 'v3.3.2-20260910120000',
             '## [3x3x2]\nWrong regex match.\n'
             '## [3.3.2]suffix\nWrong heading suffix.\n'
             '## [3.3.20]\nWrong version prefix.\n'
             '## [3.3.2-sb.12]\nWrong legacy notes.\n'
             '## [3.3.2] — 10 September\nBase summary.\n### Fixed\n- Correct feature.\n'
             '## [3.3.1]\nPrevious release.\n',
             'Base summary.\n### Fixed\n- Correct feature.'),
            ('timestamp exact preferred over earlier base', 'v3.3.2-20260910120000',
             '## [3.3.2]\nBase summary.\n'
             '## [3.3.2-20260910120000] — 10 September\nExact build summary.\n'
             '## [3.3.2-20260910120001]\nNext build summary.\n',
             'Exact build summary.'),
            ('timestamp exact empty does not fall back to base', 'v3.3.2-20260910120000',
             '## [3.3.2-20260910120000]\n'
             '## [3.3.2]\nBase summary.\n', None),
            ('legacy exact', 'v3.3.0-sb.12',
             '## [3x3x0-sbx12]\nWrong regex match.\n'
             '## [3.3.0-sb.12]\nLegacy summary.\n'
             '## [3.3.0]\nBase summary.\n', 'Legacy summary.'),
            ('legacy no base fallback', 'v3.3.0-sb.12',
             '## [3.3.0]\nBase summary.\n', None),
            ('ordinary version exact', 'v3.3.2',
             '## [3.3.20]\nWrong version prefix.\n'
             '## [3.3.2]\tRelease\nOrdinary summary.\n'
             '## Other section\nUnrelated content.\n', 'Ordinary summary.'),
            ('malformed timestamp no base fallback', 'v3.3.2-2026091012000',
             '## [3.3.2]\nBase summary.\n', None),
            ('missing changelog', 'v3.3.2-20260910120000', None, None),
        )
        fake_commands = '''
git() {
  case "$1" in
    rev-parse) printf '%s\\n' "$SOURCE_SHA" ;;
    ls-remote) return 2 ;;
    *) return 99 ;;
  esac
}
gh() { return 0; }
'''
        for job_name, step_name, output_name in (
            ('publish-release', 'Extract release notes from CHANGELOG', 'RELEASE_BODY.md'),
            ('upload-stable-candidate-artifact', 'Publish new Beta Pre-release', 'BETA_NOTES.md'),
        ):
            _, body = field(steps(self.jobs[job_name])[step_name], 'run', 8)
            for scenario, release_tag, changelog, expected in cases:
                with self.subTest(job=job_name, scenario=scenario), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    if changelog is not None:
                        (root / 'CHANGELOG.md').write_text(changelog, encoding='utf-8')
                    environment = dict(os.environ)
                    environment.update({
                        'SOURCE_SHA': 'a' * 40, 'RELEASE_TAG': release_tag,
                        'GITHUB_REPOSITORY': 'blindtechnique/keen-pbr-sb',
                    })
                    result = subprocess.run(
                        ['bash', '-c', fake_commands + textwrap.dedent(body)],
                        cwd=root, env=environment, text=True, capture_output=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    notes = (root / output_name).read_text(encoding='utf-8').strip()
                    if expected is not None:
                        self.assertEqual(notes, expected)
                    else:
                        self.assertIn('CHANGELOG', notes)
                        self.assertNotIn('Base summary.', notes)

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

from __future__ import annotations

import json
from datetime import datetime, timezone
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RESOLVER = ROOT / "build_scripts" / "resolve-release-source.py"


def git(repository: Path, *arguments: str, env: dict[str, str] | None = None) -> str:
    return subprocess.run(
        ["git", *arguments], cwd=repository, check=True, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, env=env,
    ).stdout.strip()


@unittest.skipUnless(shutil.which("git"), "git is required")
class ResolveReleaseSourceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        cls.remote = cls.root / "remote.git"
        cls.repo = cls.root / "checkout"
        cls.remote.mkdir()
        cls.repo.mkdir()
        git(cls.remote, "init", "--bare", "-q")
        git(cls.repo, "init", "-q")
        git(cls.repo, "config", "user.email", "release-test@example.invalid")
        git(cls.repo, "config", "user.name", "Release source test")
        git(cls.repo, "config", "commit.gpgsign", "false")
        git(cls.repo, "config", "tag.gpgsign", "false")
        git(cls.repo, "remote", "add", "origin", str(cls.remote))
        cls.commit_time = 1788998400
        cls.release_tag = "v3.3.0-sb.12"
        cls.release_sha = cls.commit_source("3.3.0", "12", cls.release_tag)
        git(cls.repo, "tag", cls.release_tag)
        cls.timestamp_tag = cls.timestamp_tag_for("3.3.0", cls.release_sha)
        git(cls.repo, "tag", cls.timestamp_tag)
        git(cls.repo, "tag", "releases/v-nested")
        for channel in ("alpha", "beta", "next"):
            git(cls.repo, "tag", f"{channel}-123-1")
        cls.annotated_tag = "v3.3.1-sb.13"
        cls.annotated_sha = cls.commit_source("3.3.1", "13", cls.annotated_tag)
        git(cls.repo, "tag", "-a", cls.annotated_tag, "-m", "annotated release")
        cls.annotated_object = git(cls.repo, "rev-parse", f"refs/tags/{cls.annotated_tag}")
        cls.annotated_timestamp_tag = cls.timestamp_tag_for("3.3.1", cls.annotated_sha)
        git(cls.repo, "tag", "-a", cls.annotated_timestamp_tag, "-m", "timestamp release")
        cls.annotated_timestamp_object = git(cls.repo, "rev-parse", f"refs/tags/{cls.annotated_timestamp_tag}")
        cls.invalid_sources = {
            "missing installer pin": cls.commit_source("3.3.0", "12", None),
            "different installer pin": cls.commit_source("3.3.0", "12", "v3.3.0-sb.11"),
            "timestamp release counter": cls.commit_source("3.3.0", "20260910000000", cls.release_tag),
            "invalid version": cls.commit_source("3.3.0-alpha", "12", cls.release_tag),
        }
        cls.head_tag = "v3.3.2-sb.14"
        cls.head_sha = cls.commit_source("3.3.2", "14", cls.head_tag)
        cls.head_timestamp_tag = cls.timestamp_tag_for("3.3.2", cls.head_sha)
        git(cls.repo, "branch", "alpha")
        git(cls.repo, "branch", "beta")
        git(cls.repo, "branch", "next")
        git(cls.repo, "branch", "branch-only")
        git(cls.repo, "branch", cls.release_tag)
        git(cls.repo, "push", "-q", "origin", "--all")
        git(cls.repo, "push", "-q", "origin", "--tags")
        # Make the local tag disagree with the remote. Only exact remote fetch
        # may choose the manually requested release source.
        git(cls.repo, "tag", "-f", cls.release_tag, cls.head_sha)
        git(cls.repo, "tag", "local-only")
        # The event merge object need not equal either branch tip or checkout
        # HEAD. Build a local merge object without changing any checkout ref.
        tree = git(cls.repo, "rev-parse", "HEAD^{tree}")
        cls.merge_sha = git(
            cls.repo, "commit-tree", tree, "-p", cls.head_sha, "-p", cls.release_sha,
            "-m", "pull request tested merge",
        )

    @classmethod
    def timestamp_tag_for(cls, version: str, sha: str) -> str:
        committed_at = int(git(cls.repo, "show", "-s", "--format=%ct", sha))
        stamp = datetime.fromtimestamp(committed_at, timezone.utc).strftime("%Y%m%d%H%M%S")
        return f"v{version}-{stamp}"

    @classmethod
    def commit_source(cls, version: str, release: str, pin: str | None) -> str:
        (cls.repo / "version.mk").write_text(
            f"KEEN_PBR_VERSION={version}\nKEEN_PBR_RELEASE={release}\n", encoding="utf-8",
        )
        (cls.repo / "install.sh").write_text(
            "#!/bin/sh\n" + (f"STABLE_RELEASE_TAG='{pin}'\n" if pin is not None else ""),
            encoding="utf-8",
        )
        git(cls.repo, "add", "version.mk", "install.sh")
        cls.commit_time += 1
        environment = os.environ.copy()
        # Distinct commits of the same semantic version must get distinct
        # build tags; a non-UTC committer zone must not change their UTC ID.
        environment["GIT_COMMITTER_DATE"] = f"@{cls.commit_time} +0530"
        environment["GIT_AUTHOR_DATE"] = f"@{cls.commit_time - 3600} -0700"
        git(cls.repo, "commit", "-qm", "release identity fixture", env=environment)
        return git(cls.repo, "rev-parse", "HEAD")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def resolve(
        self, event: str, ref: str, *, tag: str = "", sha: str | None = None,
        github_output: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        command = [
            sys.executable, str(RESOLVER), "--repository", str(self.repo),
            "--event-name", event, "--ref", ref,
            "--sha", self.head_sha if sha is None else sha, f"--release-tag={tag}",
        ]
        if github_output is not None:
            command.extend(["--github-output", str(github_output)])
        environment = os.environ.copy()
        # All fetch fixtures are local; the test never contacts a provider.
        environment["GIT_ALLOW_PROTOCOL"] = "file"
        return subprocess.run(
            command, cwd=self.repo, env=environment, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20,
        )

    def successful(self, result: subprocess.CompletedProcess[str]) -> dict[str, object]:
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def assert_architectures(self, output: dict[str, object], expected: list[str]) -> None:
        self.assertEqual(
            [item["arch"] for item in output["build_matrix"]["include"]], expected,
        )

    def test_manual_release_uses_exact_remote_tag_from_each_branch(self) -> None:
        for ref in ("refs/heads/main", "refs/heads/alpha", "refs/heads/beta", "refs/heads/next"):
            for tag, expected_sha in (
                (self.release_tag, self.release_sha), (self.annotated_tag, self.annotated_sha),
                (self.timestamp_tag, self.release_sha), (self.annotated_timestamp_tag, self.annotated_sha),
            ):
                with self.subTest(ref=ref, tag=tag):
                    output = self.successful(self.resolve("workflow_dispatch", ref, tag=tag))
                    self.assertEqual(output["source_sha"], expected_sha)
                    self.assertEqual(output["release_tag"], tag)
                    self.assertEqual(output["release"], "true")
                    self.assertEqual(output["channel"], "stable")
                    self.assertEqual(output["candidate"], "false")
                    self.assert_architectures(output, ["aarch64", "mips", "mipsel"])
                    self.assertEqual(git(self.repo, "rev-parse", "HEAD"), self.head_sha)

    def test_manual_prerelease_tag_cannot_enter_stable_publisher(self) -> None:
        for channel in ("alpha", "beta", "next"):
            for branch in ("main", "alpha", "beta", "next"):
                with self.subTest(channel=channel, branch=branch):
                    output_path = self.root / "prerelease-output"
                    output_path.write_text("previous=value\n", encoding="utf-8")
                    result = self.resolve(
                        "workflow_dispatch", f"refs/heads/{branch}",
                        tag=f"{channel}-123-1", github_output=output_path,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, "")
                    self.assertIn(f"rerun the original {channel} workflow", result.stderr)
                    self.assertEqual(output_path.read_text(encoding="utf-8"), "previous=value\n")

    def test_prerelease_tag_ref_cannot_enter_stable_publisher(self) -> None:
        for channel in ("alpha", "beta", "next"):
            for event in ("push", "workflow_dispatch"):
                with self.subTest(channel=channel, event=event):
                    result = self.resolve(event, f"refs/tags/{channel}-123-1")
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, "")
                    self.assertIn(f"rerun the original {channel} workflow", result.stderr)

    def test_missing_remote_tag_never_falls_back_to_branch_sha_or_local_tag(self) -> None:
        for tag in ("branch-only", "local-only", "not-present", self.head_sha):
            with self.subTest(tag=tag):
                output_path = self.root / "failed-output"
                output_path.write_text("previous=value\n", encoding="utf-8")
                result = self.resolve("workflow_dispatch", "refs/heads/alpha", tag=tag, github_output=output_path)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertEqual(output_path.read_text(encoding="utf-8"), "previous=value\n")

    def test_invalid_tag_cannot_be_a_revision_expression_or_output_injection(self) -> None:
        for tag in ("refs/tags/v-light", "../v-light", "v-light^{commit}", "v-light\nrelease=false", " "):
            with self.subTest(tag=tag):
                result = self.resolve("workflow_dispatch", "refs/heads/main", tag=tag)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")

    def test_tag_events_preserve_event_commit_instead_of_current_tag_tip(self) -> None:
        for event in ("push", "workflow_dispatch"):
            with self.subTest(event=event):
                output = self.successful(self.resolve(event, f"refs/tags/{self.release_tag}", sha=self.release_sha))
                self.assertEqual(output["source_sha"], self.release_sha)
                self.assertEqual(output["release_tag"], self.release_tag)
                self.assertEqual(output["release"], "true")
                self.assertEqual(output["channel"], "stable")
                self.assert_architectures(output, ["aarch64", "mips", "mipsel"])
        annotated = self.successful(self.resolve("push", f"refs/tags/{self.annotated_tag}", sha=self.annotated_object))
        self.assertEqual(annotated["source_sha"], self.annotated_sha)

    def test_timestamp_tags_must_match_their_event_commit_build_identity(self) -> None:
        for event in ("push", "workflow_dispatch"):
            with self.subTest(event=event):
                output = self.successful(self.resolve(event, f"refs/tags/{self.timestamp_tag}", sha=self.release_sha))
                self.assertEqual(output["source_sha"], self.release_sha)
                self.assertEqual(output["release_tag"], self.timestamp_tag)
                self.assertEqual(output["release"], "true")
                self.assertEqual(output["candidate"], "false")
                self.assert_architectures(output, ["aarch64", "mips", "mipsel"])
        annotated = self.successful(self.resolve(
            "push", f"refs/tags/{self.annotated_timestamp_tag}", sha=self.annotated_timestamp_object,
        ))
        self.assertEqual(annotated["source_sha"], self.annotated_sha)

    def test_manual_input_takes_precedence_over_dispatch_tag_ref(self) -> None:
        output = self.successful(self.resolve("workflow_dispatch", "refs/tags/other", tag=self.annotated_tag))
        self.assertEqual(output["source_sha"], self.annotated_sha)
        self.assertEqual(output["release_tag"], self.annotated_tag)

    def test_all_branch_defaults_keep_event_sha(self) -> None:
        for event in ("push", "workflow_dispatch"):
            for branch in ("alpha", "beta", "next", "main"):
                with self.subTest(event=event, branch=branch):
                    output = self.successful(self.resolve(event, f"refs/heads/{branch}", sha=self.release_sha))
                    self.assertEqual(output["source_sha"], self.release_sha)
                    self.assertEqual(output["release"], "false")
                    self.assertEqual(output["release_tag"], self.timestamp_tag if branch == "main" else "")
                    self.assertEqual(output["candidate"], "true" if branch == "main" else "false")
                    self.assertEqual(output["channel"], {"main": "stable", "beta": "none"}.get(branch, branch))
                    self.assert_architectures(output, ["aarch64", "mips", "mipsel"] if branch in ("main", "beta") else ["aarch64"])

    def test_pull_request_keeps_merge_sha_and_cannot_publish_a_release(self) -> None:
        output = self.successful(self.resolve(
            "pull_request", "refs/pull/23/merge", sha=self.merge_sha, tag="v-light",
        ))
        self.assertEqual(output["source_sha"], self.merge_sha)
        self.assertEqual(output["release"], "false")
        self.assertEqual(output["channel"], "none")
        self.assert_architectures(output, ["aarch64"])

    def test_non_dispatch_input_does_not_override_source_or_enable_release(self) -> None:
        output = self.successful(self.resolve("push", "refs/heads/alpha", tag="v-light"))
        self.assertEqual(output["source_sha"], self.head_sha)
        self.assertEqual(output["release"], "false")
        self.assertEqual(output["channel"], "alpha")

    def test_default_source_requires_full_resolvable_event_sha(self) -> None:
        for sha in ("HEAD", "alpha", self.head_sha[:12], "0" * 40, "a" * 41, "a" * 63):
            with self.subTest(sha=sha):
                result = self.resolve("push", "refs/heads/alpha", sha=sha)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")

    def test_github_output_matches_stdout_and_preserves_previous_keys(self) -> None:
        output_path = self.root / "github-output"
        output_path.write_text("previous=value\n", encoding="utf-8")
        output = self.successful(self.resolve("workflow_dispatch", "refs/heads/next", tag=self.release_tag, github_output=output_path))
        fields = dict(line.split("=", 1) for line in output_path.read_text(encoding="utf-8").splitlines())
        self.assertEqual(fields.pop("previous"), "value")
        fields["build_matrix"] = json.loads(fields["build_matrix"])
        self.assertEqual(fields, output)

    def test_main_timestamp_releases_do_not_require_legacy_installer_pin_or_counter(self) -> None:
        for reason, sha in self.invalid_sources.items():
            with self.subTest(reason=reason):
                result = self.resolve("push", "refs/heads/main", sha=sha)
                if reason == "invalid version":
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, "")
                else:
                    output = self.successful(result)
                    self.assertEqual(output["release_tag"], self.timestamp_tag_for("3.3.0", sha))
                    self.assertEqual(output["candidate"], "true")
                # Development channels and PRs do not need a release pin.
                for branch in ("alpha", "next"):
                    output = self.successful(self.resolve("push", f"refs/heads/{branch}", sha=sha))
                    self.assertEqual(output["candidate"], "false")
                self.successful(self.resolve("pull_request", "refs/pull/23/merge", sha=sha))

    def test_same_base_version_uses_newer_commit_utc_timestamp_without_release_bump(self) -> None:
        first = self.successful(self.resolve("push", "refs/heads/main", sha=self.release_sha))
        newer_sha = self.invalid_sources["missing installer pin"]
        second = self.successful(self.resolve("push", "refs/heads/main", sha=newer_sha))
        self.assertTrue(first["release_tag"].startswith("v3.3.0-"))
        self.assertTrue(second["release_tag"].startswith("v3.3.0-"))
        self.assertGreater(second["release_tag"], first["release_tag"])
        repeated = self.successful(self.resolve("workflow_dispatch", "refs/heads/main", sha=newer_sha))
        self.assertEqual(repeated["release_tag"], second["release_tag"])

    @unittest.skipUnless(shutil.which("bash"), "bash is required")
    def test_timestamp_tag_matches_shared_package_version_resolver(self) -> None:
        environment = os.environ.copy()
        environment.pop("KEEN_PBR_RELEASE_OVERRIDE", None)
        environment["TZ"] = "Pacific/Honolulu"
        result = subprocess.run(
            ["bash", str(ROOT / "build_scripts" / "resolve-version.sh"), "release", str(self.repo)],
            env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        output = self.successful(self.resolve("push", "refs/heads/main"))
        self.assertEqual(output["release_tag"], f"v3.3.2-{result.stdout.strip()}")
        self.assertEqual(output["release_tag"], self.head_timestamp_tag)

    def test_stable_tag_must_match_version_and_installer_in_the_event_commit(self) -> None:
        for tag, sha in (
            (self.release_tag, self.head_sha),
            ("releases/v-nested", self.release_sha),
            ("v3.3.0-20260910000000", self.release_sha),
            (self.timestamp_tag, self.head_sha),
        ):
            with self.subTest(tag=tag):
                result = self.resolve("push", f"refs/tags/{tag}", sha=sha)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("release_tag must match", result.stderr)
        for reason, sha in self.invalid_sources.items():
            with self.subTest(reason=reason):
                result = self.resolve("push", f"refs/tags/{self.release_tag}", sha=sha)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()

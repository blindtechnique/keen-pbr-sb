from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RESOLVER = ROOT / "build_scripts" / "resolve-release-source.py"


def git(repository: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments], cwd=repository, check=True, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
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
        git(cls.repo, "commit", "--allow-empty", "-qm", "release source")
        cls.release_sha = git(cls.repo, "rev-parse", "HEAD")
        git(cls.repo, "tag", "v-light")
        git(cls.repo, "tag", "-a", "v-annotated", "-m", "annotated release")
        cls.annotated_object = git(cls.repo, "rev-parse", "refs/tags/v-annotated")
        git(cls.repo, "tag", "releases/v-nested")
        git(cls.repo, "commit", "--allow-empty", "-qm", "newer branch source")
        cls.head_sha = git(cls.repo, "rev-parse", "HEAD")
        git(cls.repo, "branch", "alpha")
        git(cls.repo, "branch", "next")
        git(cls.repo, "branch", "branch-only")
        git(cls.repo, "branch", "v-light")
        git(cls.repo, "push", "-q", "origin", "--all")
        git(cls.repo, "push", "-q", "origin", "--tags")
        # Make the local tag disagree with the remote. Only exact remote fetch
        # may choose the manually requested release source.
        git(cls.repo, "tag", "-f", "v-light", cls.head_sha)
        git(cls.repo, "tag", "local-only")
        # The event merge object need not equal either branch tip or checkout
        # HEAD. Build a local merge object without changing any checkout ref.
        tree = git(cls.repo, "rev-parse", "HEAD^{tree}")
        cls.merge_sha = git(
            cls.repo, "commit-tree", tree, "-p", cls.head_sha, "-p", cls.release_sha,
            "-m", "pull request tested merge",
        )

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
        for ref in ("refs/heads/main", "refs/heads/alpha", "refs/heads/next"):
            for tag in ("v-light", "v-annotated", "releases/v-nested"):
                with self.subTest(ref=ref, tag=tag):
                    output = self.successful(self.resolve("workflow_dispatch", ref, tag=tag))
                    self.assertEqual(output["source_sha"], self.release_sha)
                    self.assertEqual(output["release_tag"], tag)
                    self.assertEqual(output["release"], "true")
                    self.assertEqual(output["channel"], "none")
                    self.assert_architectures(output, ["aarch64", "mips", "mipsel"])
                    self.assertEqual(git(self.repo, "rev-parse", "HEAD"), self.head_sha)

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
                output = self.successful(self.resolve(event, "refs/tags/v-light", sha=self.head_sha))
                self.assertEqual(output["source_sha"], self.head_sha)
                self.assertEqual(output["release_tag"], "v-light")
                self.assertEqual(output["release"], "true")
                self.assertEqual(output["channel"], "none")
                self.assert_architectures(output, ["aarch64", "mips", "mipsel"])
        annotated = self.successful(self.resolve("push", "refs/tags/v-annotated", sha=self.annotated_object))
        self.assertEqual(annotated["source_sha"], self.release_sha)

    def test_manual_input_takes_precedence_over_dispatch_tag_ref(self) -> None:
        output = self.successful(self.resolve("workflow_dispatch", "refs/tags/other", tag="v-annotated"))
        self.assertEqual(output["source_sha"], self.release_sha)
        self.assertEqual(output["release_tag"], "v-annotated")

    def test_alpha_next_and_main_defaults_keep_event_sha(self) -> None:
        for event in ("push", "workflow_dispatch"):
            for branch in ("alpha", "next", "main"):
                with self.subTest(event=event, branch=branch):
                    output = self.successful(self.resolve(event, f"refs/heads/{branch}", sha=self.release_sha))
                    self.assertEqual(output["source_sha"], self.release_sha)
                    self.assertEqual(output["release"], "false")
                    self.assertEqual(output["release_tag"], "")
                    self.assertEqual(output["channel"], "none" if branch == "main" else branch)
                    self.assert_architectures(output, ["aarch64", "mips", "mipsel"] if branch == "main" else ["aarch64"])

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
        output = self.successful(self.resolve("workflow_dispatch", "refs/heads/next", tag="v-light", github_output=output_path))
        fields = dict(line.split("=", 1) for line in output_path.read_text(encoding="utf-8").splitlines())
        self.assertEqual(fields.pop("previous"), "value")
        fields["build_matrix"] = json.loads(fields["build_matrix"])
        self.assertEqual(fields, output)


if __name__ == "__main__":
    unittest.main()

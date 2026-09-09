#!/usr/bin/env python3
"""Pin every release-workflow job to one event commit or exact requested tag."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


ARCHITECTURES = [
    {"config": "aarch64-3.10", "arch": "aarch64"},
    {"config": "mips-3.4", "arch": "mips"},
    {"config": "mipsel-3.4", "arch": "mipsel"},
]


class ResolutionError(ValueError):
    pass


def git(repository: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(
            ["git", *arguments],
            cwd=repository,
            check=True,
            text=True,
            encoding="utf-8",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as error:
        # Do not print the configured remote URL: it can contain credentials.
        raise ResolutionError(f"git {arguments[0]} failed while resolving release source") from error
    return result.stdout.strip()


def tag_ref(repository: Path, name: str) -> str:
    if not name or name.startswith("refs/"):
        raise ResolutionError("release_tag must be a short tag name, not a refs/ path")
    if name.startswith(("alpha-", "beta-", "next-")):
        channel = name.split("-", 1)[0]
        raise ResolutionError(
            f"{channel} prerelease tags cannot be published as stable; "
            f"rerun the original {channel} workflow instead"
        )
    reference = f"refs/tags/{name}"
    try:
        git(repository, "check-ref-format", reference)
    except ResolutionError as error:
        raise ResolutionError("release_tag is not a valid Git tag name") from error
    return reference


def resolve_source(
    repository: Path,
    *,
    event_name: str,
    ref: str,
    sha: str,
    requested_tag: str = "",
) -> dict[str, object]:
    release_tag = ""
    if event_name == "workflow_dispatch" and requested_tag:
        reference = tag_ref(repository, requested_tag)
        # An exact tag ref cannot resolve to a branch with the same name, a
        # stale local tag, or an arbitrary commit supplied as release_tag.
        git(repository, "fetch", "--no-tags", "--depth=1", "origin", reference)
        source_sha = git(repository, "rev-parse", "--verify", "FETCH_HEAD^{commit}")
        release_tag = requested_tag
    else:
        if not re.fullmatch(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})", sha):
            raise ResolutionError("sha must be the full immutable event object ID")
        source_sha = git(repository, "rev-parse", "--verify", f"{sha}^{{commit}}")
        if event_name in ("push", "workflow_dispatch") and ref.startswith("refs/tags/"):
            release_tag = ref.removeprefix("refs/tags/")
            tag_ref(repository, release_tag)
        # In particular, pull_request keeps github.sha (the tested merge
        # commit), not the source branch HEAD or a subsequently moved ref.

    is_release = bool(release_tag)
    channel = "none"
    if not is_release and event_name in ("push", "workflow_dispatch"):
        if ref in ("refs/heads/alpha", "refs/heads/beta", "refs/heads/next"):
            channel = ref.removeprefix("refs/heads/")
    single_architecture = not is_release and (
        ref in ("refs/heads/alpha", "refs/heads/next") or event_name == "pull_request"
    )
    return {
        "source_sha": source_sha,
        "release_tag": release_tag,
        "release": "true" if is_release else "false",
        "channel": channel,
        "build_matrix": {"include": ARCHITECTURES[:1] if single_architecture else ARCHITECTURES},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--release-tag", default="")
    parser.add_argument("--repository", type=Path, default=Path("."))
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()
    try:
        output = resolve_source(
            args.repository,
            event_name=args.event_name,
            ref=args.ref,
            sha=args.sha,
            requested_tag=args.release_tag,
        )
        if args.github_output is not None:
            with args.github_output.open("a", encoding="utf-8", newline="\n") as destination:
                for key, value in output.items():
                    encoded = json.dumps(value, separators=(",", ":")) if isinstance(value, dict) else value
                    destination.write(f"{key}={encoded}\n")
        print(json.dumps(output, separators=(",", ":")))
    except (ResolutionError, OSError) as error:
        print(f"release source: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

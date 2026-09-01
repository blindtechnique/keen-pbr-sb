from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RESOLVER = ROOT / "build_scripts" / "resolve-version.sh"


def run(
    command: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        check=False,
        text=True,
        timeout=30,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def write_version(workspace: Path) -> None:
    (workspace / "version.mk").write_text(
        "KEEN_PBR_VERSION=3.1.1\nKEEN_PBR_RELEASE=12\n",
        encoding="utf-8",
    )


def copy_fixture(workspace: Path, relative_paths: tuple[str, ...]) -> None:
    write_version(workspace)
    for relative_path in relative_paths:
        source = ROOT / relative_path
        destination = workspace / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(source, destination)
        else:
            shutil.copy2(source, destination)


def write_executable(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def pipeline_environment(fake_bin: Path, trace: Path, commit: str) -> dict[str, str]:
    environment = os.environ.copy()
    environment["PATH"] = f"{fake_bin}{os.pathsep}{environment.get('PATH', '')}"
    environment["IDENTITY_TRACE"] = str(trace)
    environment["KEEN_PBR_COMMIT_OVERRIDE"] = commit
    environment["KEEN_PBR_RELEASE_OVERRIDE"] = "20260827010101"
    # These identity-only fixtures intentionally supply a detached synthetic
    # bundle. Production source builds use the fingerprinted default mode.
    environment["KEEN_PBR_FRONTEND_DIST_MODE"] = "prebuilt"
    return environment


class BuildIdentityTest(unittest.TestCase):
    def resolve(
        self,
        workspace: Path,
        *,
        override: str | None = None,
        path: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.pop("KEEN_PBR_COMMIT_OVERRIDE", None)
        if override is not None:
            environment["KEEN_PBR_COMMIT_OVERRIDE"] = override
        if path is not None:
            environment["PATH"] = path
        return run(
            ["bash", str(RESOLVER), "commit", str(workspace)],
            env=environment,
        )

    def test_clean_dirty_override_and_exported_tree_resolution(self) -> None:
        if shutil.which("git") is None:
            self.skipTest("git is required")
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory) / "repo"
            workspace.mkdir()
            write_version(workspace)
            (workspace / "tracked.txt").write_text("clean\n", encoding="utf-8")
            for command in (
                ["git", "init", "-q"],
                ["git", "config", "user.email", "identity@example.invalid"],
                ["git", "config", "user.name", "Build Identity Test"],
                ["git", "add", "version.mk", "tracked.txt"],
                ["git", "commit", "-q", "-m", "fixture"],
            ):
                result = run(command, cwd=workspace)
                self.assertEqual(result.returncode, 0, result.stderr)

            expected = run(
                ["git", "rev-parse", "--short=12", "HEAD"], cwd=workspace
            ).stdout.strip()
            clean = self.resolve(workspace)
            self.assertEqual(clean.returncode, 0, clean.stderr)
            self.assertEqual(clean.stdout, expected)

            untracked_path = workspace / "untracked.cpp"
            untracked_path.write_text("uncommitted source\n", encoding="utf-8")
            untracked = self.resolve(workspace)
            self.assertEqual(untracked.returncode, 0, untracked.stderr)
            self.assertEqual(untracked.stdout, f"{expected}-dirty")
            untracked_path.unlink()

            (workspace / "tracked.txt").write_text("dirty\n", encoding="utf-8")
            dirty = self.resolve(workspace)
            self.assertEqual(dirty.returncode, 0, dirty.stderr)
            self.assertEqual(dirty.stdout, f"{expected}-dirty")

            override = self.resolve(workspace, override="0123456789abcdef-dirty")
            self.assertEqual(override.returncode, 0, override.stderr)
            self.assertEqual(override.stdout, "0123456789abcdef-dirty")

            exported = Path(directory) / "exported"
            exported.mkdir()
            write_version(exported)
            unknown = self.resolve(exported)
            self.assertEqual(unknown.returncode, 0, unknown.stderr)
            self.assertEqual(unknown.stdout, "unknown")

            exported_release = run(
                ["bash", str(RESOLVER), "release", str(exported)]
            )
            self.assertEqual(exported_release.returncode, 0, exported_release.stderr)
            self.assertRegex(exported_release.stdout, r"^[0-9]{14}\n?$")
            self.assertNotEqual(exported_release.stdout.strip(), "12")

    def test_git_status_failure_is_never_reported_as_clean(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory) / "workspace"
            fake_bin = Path(directory) / "bin"
            workspace.mkdir()
            fake_bin.mkdir()
            write_version(workspace)
            fake_git = fake_bin / "git"
            fake_git.write_text(
                "#!/bin/sh\n"
                "case \" $* \" in\n"
                "  *\" rev-parse --is-inside-work-tree \"*) echo true ;;\n"
                "  *\" rev-parse --short=12 HEAD \"*) echo 0123456789ab ;;\n"
                "  *\" status --porcelain --untracked-files=normal \"*) exit 2 ;;\n"
                "  *) exit 2 ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            fake_git.chmod(0o755)
            result = self.resolve(
                workspace,
                path=f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "0123456789ab-dirty")

    def test_invalid_overrides_fail_before_packaging(self) -> None:
        invalid_values = (
            "abc",
            "ABCDEF012345",
            "0123456789ab extra",
            "0123456789ab-clean",
            "0123456789ab\nDescription: injected",
            "a" * 65,
        )
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            write_version(workspace)
            for value in invalid_values:
                with self.subTest(value=value):
                    result = self.resolve(workspace, override=value)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("Invalid KEEN_PBR commit identity", result.stderr)

    def test_cmake_rejects_malformed_explicit_identity(self) -> None:
        if shutil.which("cmake") is None:
            self.skipTest("cmake is required")
        invalid_values = ("abc", "ABCDEF012345", "0123456789ab-clean")
        with tempfile.TemporaryDirectory() as directory:
            for index, value in enumerate(invalid_values):
                with self.subTest(value=value):
                    build_dir = Path(directory) / f"build-{index}"
                    result = run(
                        [
                            "cmake",
                            "-S",
                            str(ROOT),
                            "-B",
                            str(build_dir),
                            f"-DKEEN_PBR_COMMIT:STRING={value}",
                            "-DWITH_API=OFF",
                        ]
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("KEEN_PBR_COMMIT must be", result.stderr)

    def test_make_override_is_validated_and_wins_before_interpolation(self) -> None:
        if shutil.which("make") is None:
            self.skipTest("GNU make is required")
        rule = "print-identity: ; @printf '%s' '$(KEEN_PBR_COMMIT)'"
        environment = os.environ.copy()
        environment["KEEN_PBR_COMMIT_OVERRIDE"] = "0123456789abcdef"
        accepted = run(
            [
                "make",
                "--no-print-directory",
                "-s",
                "--eval",
                rule,
                "KEEN_PBR_COMMIT=caller-must-not-bypass-validation",
                "KEEN_PBR_COMMIT_RESOLVED=internal-must-not-be-overridden",
                "print-identity",
            ],
            cwd=ROOT,
            env=environment,
        )
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertEqual(accepted.stdout, "0123456789abcdef")

        environment["KEEN_PBR_COMMIT_OVERRIDE"] = "ABCDEF012345"
        rejected = run(
            [
                "make",
                "--no-print-directory",
                "-s",
                "--eval",
                rule,
                "print-identity",
            ],
            cwd=ROOT,
            env=environment,
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("Failed to resolve a valid KEEN_PBR_COMMIT", rejected.stderr)

    def test_no_git_platform_scripts_preserve_explicit_identity(self) -> None:
        commit = "0123456789abcdef0123456789abcdef01234567"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / "fake-bin"
            write_executable(
                fake_bin / "make",
                "#!/bin/sh\n"
                "set -eu\n"
                "case \" $* \" in\n"
                "  *\" defconfig \"*)\n"
                "    printf '%s\\n' CONFIG_PACKAGE_keen-pbr=m >> .config\n"
                "    printf '%s\\n' CONFIG_PACKAGE_keen-pbr-headless=m >> .config\n"
                "    printf '%s\\n' CONFIG_PACKAGE_conntrack=m >> .config\n"
                "    ;;\n"
                "  *\" package/keen-pbr/compile \"*)\n"
                "    commit=\n"
                "    for argument in \"$@\"; do\n"
                "      case \"$argument\" in\n"
                "        KEEN_PBR_COMMIT=*) commit=${argument#*=} ;;\n"
                "      esac\n"
                "    done\n"
                "    [ -n \"$commit\" ] || exit 91\n"
                "    printf '%s\\n' \"$commit\" >> \"$IDENTITY_TRACE\"\n"
                "    ;;\n"
                "esac\n",
            )

            # Keenetic/Entware: the source copied into the feed has no .git.
            keenetic_workspace = root / "keenetic-workspace"
            keenetic_workspace.mkdir()
            copy_fixture(
                keenetic_workspace,
                (
                    "build_scripts/resolve-version.sh",
                    "build_scripts/ensure-frontend-dist.sh",
                    "build_scripts/build-keenetic-package.sh",
                    "packages/keenetic/packages.config",
                ),
            )
            self.assertFalse((keenetic_workspace / ".git").exists())
            keenetic_dist = keenetic_workspace / "frontend/dist"
            keenetic_dist.mkdir(parents=True)
            (keenetic_dist / "index.html").write_text("ok", encoding="utf-8")
            (keenetic_dist / ".keen-pbr-version").write_text(
                "v3.1.1-20260827010101\n", encoding="utf-8"
            )
            transport = root / "transport-manager"
            transport.write_bytes(b"fixture")
            entware = root / "entware"
            (entware / "scripts").mkdir(parents=True)
            (entware / "package/feeds/keenPbr/keen-pbr").mkdir(parents=True)
            (entware / "feeds.conf").write_text("", encoding="utf-8")
            write_executable(entware / "scripts/feeds", "#!/bin/sh\nexit 0\n")
            write_executable(
                entware / "staging_dir/host/bin/ninja",
                "#!/bin/sh\nexit 0\n",
            )
            keenetic_trace = root / "keenetic.trace"
            keenetic_env = pipeline_environment(fake_bin, keenetic_trace, commit)
            keenetic_env["KEEN_PBR_FRONTEND_DIST"] = str(keenetic_dist)
            keenetic_env["KEEN_PBR_TRANSPORT_MANAGER_BIN"] = str(transport)
            keenetic_env["KEEN_PBR_JOBS"] = "1"
            keenetic = run(
                [
                    "sh",
                    str(
                        keenetic_workspace
                        / "build_scripts/build-keenetic-package.sh"
                    ),
                    str(keenetic_workspace),
                    str(entware),
                ],
                env=keenetic_env,
            )
            self.assertEqual(keenetic.returncode, 0, keenetic.stderr)
            self.assertEqual(keenetic_trace.read_text(encoding="utf-8"), f"{commit}\n")

            # OpenWrt: feeds and compiler are faked, but the production script
            # executes every handoff step through the SDK make invocation.
            openwrt_workspace = root / "openwrt-workspace"
            openwrt_workspace.mkdir()
            copy_fixture(
                openwrt_workspace,
                (
                    "build_scripts/resolve-version.sh",
                    "build_scripts/ensure-frontend-dist.sh",
                    "build_scripts/build-openwrt-package.sh",
                    "packages/openwrt/packages.config",
                    "packages/openwrt/keen-pbr",
                ),
            )
            self.assertFalse((openwrt_workspace / ".git").exists())
            openwrt_dist = openwrt_workspace / "frontend/dist"
            openwrt_dist.mkdir(parents=True)
            (openwrt_dist / "index.html").write_text("ok", encoding="utf-8")
            (openwrt_dist / ".keen-pbr-version").write_text(
                "v3.1.1-20260827010101\n", encoding="utf-8"
            )
            sdk = root / "openwrt-sdk"
            (sdk / "scripts").mkdir(parents=True)
            (sdk / "staging_dir").mkdir()
            (sdk / "package").mkdir()
            write_executable(
                sdk / "scripts/feeds",
                "#!/bin/sh\n"
                "set -eu\n"
                "if [ \"${1:-}\" = update ]; then\n"
                "  mkdir -p feeds/base feeds/packages feeds/luci feeds/routing feeds/telephony\n"
                "fi\n",
            )
            openwrt_trace = root / "openwrt.trace"
            openwrt_env = pipeline_environment(fake_bin, openwrt_trace, commit)
            openwrt_env["KEEN_PBR_FRONTEND_DIST"] = str(openwrt_dist)
            openwrt = run(
                [
                    "bash",
                    str(
                        openwrt_workspace
                        / "build_scripts/build-openwrt-package.sh"
                    ),
                    str(openwrt_workspace),
                    str(sdk),
                ],
                env=openwrt_env,
            )
            self.assertEqual(openwrt.returncode, 0, openwrt.stderr)
            self.assertEqual(openwrt_trace.read_text(encoding="utf-8"), f"{commit}\n")

            # Debian: both .git-free source copies must carry the same token
            # into their independent dpkg-buildpackage processes.
            debian_workspace = root / "debian-workspace"
            debian_workspace.mkdir()
            copy_fixture(
                debian_workspace,
                (
                    "build_scripts/resolve-version.sh",
                    "build_scripts/ensure-frontend-dist.sh",
                    "build_scripts/build-debian-packages.sh",
                    "packages/debian/full/debian",
                    "packages/debian/headless/debian",
                ),
            )
            self.assertFalse((debian_workspace / ".git").exists())
            debian_dist = debian_workspace / "frontend/dist"
            debian_dist.mkdir(parents=True)
            (debian_dist / "index.html").write_text("ok", encoding="utf-8")
            (debian_dist / ".keen-pbr-version").write_text(
                "v3.1.1-20260827010101\n", encoding="utf-8"
            )
            write_executable(
                debian_workspace / "build_scripts/collect-debian.sh",
                "#!/bin/sh\nexit 0\n",
            )
            write_executable(
                fake_bin / "dpkg-buildpackage",
                "#!/bin/sh\n"
                "set -eu\n"
                "directory=$(basename \"$PWD\")\n"
                "printf '%s:%s\\n' \"$directory\" \"$KEEN_PBR_COMMIT\" >> \"$IDENTITY_TRACE\"\n"
                "case \"$(basename \"$PWD\")\" in\n"
                "  full) touch ../keen-pbr_1_amd64.deb ;;\n"
                "  headless) touch ../keen-pbr-headless_1_amd64.deb ;;\n"
                "  *) exit 92 ;;\n"
                "esac\n",
            )
            debian_trace = root / "debian.trace"
            debian_env = pipeline_environment(fake_bin, debian_trace, commit)
            debian_env["KEEN_PBR_FRONTEND_DIST"] = str(debian_dist)
            release_dir = root / "debian-release"
            debian = run(
                [
                    "bash",
                    str(
                        debian_workspace
                        / "build_scripts/build-debian-packages.sh"
                    ),
                    str(debian_workspace),
                    str(release_dir),
                ],
                env=debian_env,
            )
            self.assertEqual(debian.returncode, 0, debian.stderr)
            self.assertEqual(
                debian_trace.read_text(encoding="utf-8").splitlines(),
                [f"full:{commit}", f"headless:{commit}"],
            )

    def test_all_package_pipelines_use_explicit_identity_handoff(self) -> None:
        required_snippets = {
            ".github/workflows/release-keenetic.yml": [
                "path: ${{ runner.temp }}/frontend-dist",
                'cp -a "$RUNNER_TEMP/frontend-dist/." frontend/dist/',
            ],
            "build_scripts/keenetic.mk": ["KEEN_PBR_COMMIT_OVERRIDE"],
            "build_scripts/openwrt.mk": ["KEEN_PBR_COMMIT_OVERRIDE"],
            "build_scripts/debian.mk": ["KEEN_PBR_COMMIT_OVERRIDE"],
            "build_scripts/build-keenetic-package.sh": [
                'resolve-version.sh\" commit',
                'KEEN_PBR_COMMIT=\"$KEEN_PBR_COMMIT\"',
            ],
            "build_scripts/build-openwrt-package.sh": [
                'resolve-version.sh\" commit',
                'KEEN_PBR_COMMIT=\"$KEEN_PBR_COMMIT\"',
            ],
            "build_scripts/build-debian-packages.sh": [
                'resolve-version.sh\" commit',
                'KEEN_PBR_COMMIT=\"$KEEN_PBR_COMMIT\"',
            ],
            "packages/debian/full/debian/rules": ["-DKEEN_PBR_COMMIT:STRING="],
            "packages/debian/headless/debian/rules": [
                "-DKEEN_PBR_COMMIT:STRING="
            ],
        }
        for relative_path, snippets in required_snippets.items():
            content = (ROOT / relative_path).read_text(encoding="utf-8")
            for snippet in snippets:
                with self.subTest(path=relative_path, snippet=snippet):
                    self.assertIn(snippet, content)

        for relative_path in (
            "packages/keenetic/keen-pbr/Makefile",
            "packages/openwrt/keen-pbr/Makefile",
        ):
            content = (ROOT / relative_path).read_text(encoding="utf-8")
            with self.subTest(path=relative_path):
                self.assertIn("-DKEEN_PBR_COMMIT:STRING=$(KEEN_PBR_COMMIT)", content)
                self.assertEqual(content.count("Built from source commit"), 2)

        main = (ROOT / "src/main.cpp").read_text(encoding="utf-8")
        self.assertEqual(main.count("KEEN_PBR3_VERSION_IDENTITY_STRING"), 3)

        for relative_path in (
            "build_scripts/resolve-version.sh",
            "CMakeLists.txt",
        ):
            content = (ROOT / relative_path).read_text(encoding="utf-8")
            with self.subTest(path=relative_path, identity_scope="untracked"):
                self.assertIn("--untracked-files=normal", content)
                self.assertNotRegex(content, r"--untracked-files=no(?:\s|$)")

        workflow = (ROOT / ".github/workflows/release-keenetic.yml").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("\n          path: frontend-dist\n", workflow)


class FrontendDistFreshnessTest(unittest.TestCase):
    def test_nonempty_stale_bundle_is_rebuilt_and_fresh_bundle_is_reused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace = root / "workspace"
            fake_bin = root / "fake-bin"
            workspace.mkdir()
            copy_fixture(
                workspace,
                (
                    "build_scripts/frontend-source-id.sh",
                    "build_scripts/build-frontend.sh",
                    "build_scripts/ensure-frontend-dist.sh",
                ),
            )
            source = workspace / "frontend/src/app.txt"
            source.parent.mkdir(parents=True)
            source.write_text("current-v1\n", encoding="utf-8")
            (workspace / "frontend/package.json").write_text(
                '{"name":"fixture"}\n', encoding="utf-8"
            )

            dist = workspace / "frontend/dist"
            dist.mkdir(parents=True)
            (dist / "index.html").write_text("stale\n", encoding="utf-8")

            trace = root / "bun.trace"
            write_executable(
                fake_bin / "bun",
                "#!/bin/sh\n"
                "set -eu\n"
                "printf '%s\\n' \"$*\" >> \"$BUN_TRACE\"\n"
                "case \"${1:-} ${2:-}\" in\n"
                "  'install --frozen-lockfile') exit 0 ;;\n"
                "  'run build')\n"
                "    mkdir -p \"$KEEN_PBR_FRONTEND_OUT_DIR\"\n"
                "    cp src/app.txt \"$KEEN_PBR_FRONTEND_OUT_DIR/index.html\"\n"
                "    exit 0\n"
                "    ;;\n"
                "  *) exit 64 ;;\n"
                "esac\n",
            )
            environment = os.environ.copy()
            environment["PATH"] = (
                f"{fake_bin}{os.pathsep}{environment.get('PATH', '')}"
            )
            environment["BUN_TRACE"] = str(trace)
            ensure = workspace / "build_scripts/ensure-frontend-dist.sh"

            rebuilt = run(
                ["sh", str(ensure), str(workspace), str(dist)],
                env=environment,
            )
            self.assertEqual(rebuilt.returncode, 0, rebuilt.stderr)
            self.assertEqual(
                (dist / "index.html").read_text(encoding="utf-8"),
                "current-v1\n",
            )
            self.assertTrue((dist / ".keen-pbr-source-id").is_file())
            self.assertEqual(
                (dist / ".keen-pbr-version").read_text(encoding="utf-8"),
                "v3.1.1\n",
            )
            self.assertEqual(len(trace.read_text(encoding="utf-8").splitlines()), 2)

            reused = run(
                ["sh", str(ensure), str(workspace), str(dist)],
                env=environment,
            )
            self.assertEqual(reused.returncode, 0, reused.stderr)
            self.assertEqual(len(trace.read_text(encoding="utf-8").splitlines()), 2)

            versioned_environment = environment.copy()
            versioned_environment["KEEN_PBR_RELEASE_OVERRIDE"] = "20260827010101"
            rebuilt_for_release = run(
                ["sh", str(ensure), str(workspace), str(dist)],
                env=versioned_environment,
            )
            self.assertEqual(
                rebuilt_for_release.returncode, 0, rebuilt_for_release.stderr
            )
            self.assertEqual(
                (dist / ".keen-pbr-version").read_text(encoding="utf-8"),
                "v3.1.1-20260827010101\n",
            )
            self.assertEqual(len(trace.read_text(encoding="utf-8").splitlines()), 4)

            source.write_text("current-v2\n", encoding="utf-8")
            rebuilt_again = run(
                ["sh", str(ensure), str(workspace), str(dist)],
                env=environment,
            )
            self.assertEqual(rebuilt_again.returncode, 0, rebuilt_again.stderr)
            self.assertEqual(
                (dist / "index.html").read_text(encoding="utf-8"),
                "current-v2\n",
            )
            self.assertEqual(len(trace.read_text(encoding="utf-8").splitlines()), 6)

    def test_prebuilt_mode_is_explicit_and_frontend_builder_never_bootstraps_tools(self) -> None:
        ensure = (ROOT / "build_scripts/ensure-frontend-dist.sh").read_text(
            encoding="utf-8"
        )
        builder = (ROOT / "build_scripts/build-frontend.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("KEEN_PBR_FRONTEND_DIST_MODE", ensure)
        self.assertNotIn("curl", builder)
        self.assertNotIn("apt-get", builder)
        self.assertNotIn("pipefail", builder)


if __name__ == "__main__":
    unittest.main()

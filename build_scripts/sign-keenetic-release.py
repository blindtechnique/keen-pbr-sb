#!/usr/bin/env python3
"""Create a bounded Keenetic release manifest and authenticate it with RSA/SHA256.

The private key is read by OpenSSL from the caller's temporary secret file. Its
contents and OpenSSL diagnostics are never printed. This tool publishes no release.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
PACKAGE = re.compile(
    r"keen-pbr_(?P<version>[A-Za-z0-9][A-Za-z0-9._+-]{0,127})"
    r"_keenetic_(?P<arch>aarch64|armv7|mipsel|mips|x64)-"
    r"(?P<abi>[0-9]+(?:\.[0-9]+)*)\.ipk\Z"
)
MAX_MANIFEST_BYTES = 65536
MAX_FILES = 32


class SigningError(ValueError):
    pass


def regular_file(path: Path, description: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise SigningError(f"{description} must be a regular file, not a symlink")


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def manifest(args: argparse.Namespace) -> bytes:
    if not REPOSITORY.fullmatch(args.repository) or len(args.repository) > 160:
        raise SigningError("repository must be an owner/repository name")
    if args.channel not in {"stable", "alpha", "beta", "next"}:
        raise SigningError("channel must be stable, alpha, beta, or next")
    if not TOKEN.fullmatch(args.release) or not TOKEN.fullmatch(args.build):
        raise SigningError("release and build must be bounded portable identifiers")
    if not re.fullmatch(r"[0-9a-f]{40}", args.source):
        raise SigningError("source must be a full lowercase Git commit SHA")
    if not args.assets.is_dir() or args.assets.is_symlink():
        raise SigningError("assets must be a directory, not a symlink")
    regular_file(args.installer, "installer")
    packages = sorted(args.assets.glob("*.ipk"))
    if not packages or len(packages) + 1 > MAX_FILES:
        raise SigningError("release must contain 1 to 31 full Keenetic packages")
    rows = [
        "keen-pbr-release-v1",
        f"repository\t{args.repository}",
        f"channel\t{args.channel}",
        f"release\t{args.release}",
        f"source\t{args.source}",
        f"build\t{args.build}",
        f"file\tinstaller\tany\tany\t-\t{digest(args.installer)}\tinstall.sh",
    ]
    targets: set[tuple[str, str]] = set()
    for package in packages:
        regular_file(package, "package")
        match = PACKAGE.fullmatch(package.name)
        if match is None or len(package.name) > 255:
            raise SigningError("unexpected package filename in release assets")
        target = (match["arch"], match["abi"])
        if target in targets:
            raise SigningError("release contains duplicate architecture/ABI targets")
        targets.add(target)
        rows.append("\t".join([
            "file", "package", *target, match["version"], digest(package), package.name,
        ]))
    payload = ("\n".join(rows) + "\n").encode("ascii")
    if len(payload) > MAX_MANIFEST_BYTES:
        raise SigningError("release manifest exceeds the size limit")
    return payload


def openssl(executable: str, *arguments: str) -> bytes:
    try:
        result = subprocess.run(
            [executable, *arguments], check=True, capture_output=True, timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise SigningError("OpenSSL release signing or verification failed") from error
    return result.stdout


def sign(args: argparse.Namespace) -> None:
    executable = shutil.which("openssl")
    if executable is None:
        raise SigningError("OpenSSL is required")
    regular_file(args.key, "signing key")
    regular_file(args.public_key, "public key")
    public_description = openssl(
        executable, "rsa", "-pubin", "-in", str(args.public_key), "-text", "-noout",
    )
    # OpenSSL 1.1.1 includes the RSA prefix; OpenSSL 3.x omits it.
    first_line = public_description.splitlines()[0:1]
    if first_line not in ([b"Public-Key: (3072 bit)"], [b"RSA Public-Key: (3072 bit)"]):
        raise SigningError("release signing requires a dedicated RSA 3072-bit public key")
    # All validation happens before replacing any existing output asset.
    payload = manifest(args)
    with tempfile.TemporaryDirectory(prefix=".release-sign-", dir=args.assets) as temporary:
        stage = Path(temporary)
        staged_manifest = stage / "release-manifest.tsv"
        staged_signature = stage / "release-manifest.sig"
        staged_installer = stage / "install.sh"
        staged_manifest.write_bytes(payload)
        openssl(
            executable, "dgst", "-sha256", "-sign", str(args.key),
            "-sigopt", "rsa_padding_mode:pkcs1", "-passin", "pass:",
            "-out", str(staged_signature), str(staged_manifest),
        )
        openssl(
            executable, "dgst", "-sha256", "-verify", str(args.public_key),
            "-sigopt", "rsa_padding_mode:pkcs1", "-signature", str(staged_signature), str(staged_manifest),
        )
        shutil.copyfile(args.installer, staged_installer)
        expected_installer = payload.decode("ascii").splitlines()[6].split("\t")[5]
        if digest(staged_installer) != expected_installer:
            raise SigningError("installer changed while signing the release")
        # Detect accidental concurrent package rewrites before exposing the manifest.
        if manifest(args) != payload:
            raise SigningError("release assets changed while signing")
        staged_installer.replace(args.assets / "install.sh")
        staged_signature.replace(args.assets / "release-manifest.sig")
        staged_manifest.replace(args.assets / "release-manifest.tsv")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("assets", "installer", "key", "public-key"):
        parser.add_argument(f"--{name}", required=True, type=Path)
    for name in ("repository", "channel", "release", "source", "build"):
        parser.add_argument(f"--{name}", required=True)
    args = parser.parse_args()
    try:
        sign(args)
    except (SigningError, OSError) as error:
        # OSError may contain local paths, but never include the private key bytes.
        print(f"Release signing failed: {error}", file=sys.stderr)
        return 1
    print("Release manifest signed and verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

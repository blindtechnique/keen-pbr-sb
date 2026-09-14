"""Exercise the actual release signer and BusyBox verifier with test-only keys."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SIGNER = ROOT / "build_scripts/sign-keenetic-release.py"
VERIFIER = ROOT / "packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr/release-verify.sh"
REPOSITORY = "blindtechnique/keen-pbr-sb"
RELEASE = "v3.3.1-test"
PACKAGE = "keen-pbr_3.3.1-test_keenetic_aarch64-3.10.ipk"


@unittest.skipUnless(shutil.which("openssl") and shutil.which("sh"),
                     "OpenSSL and a POSIX shell are required")
class KeeneticReleaseSignaturesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys_temporary = tempfile.TemporaryDirectory(prefix="kpbr-test-only-signing-keys-")
        cls.keys = Path(cls.keys_temporary.name)
        cls.key = cls.keys / "TEST-ONLY-private.pem"
        cls.public = cls.keys / "TEST-ONLY-public.pem"
        cls.wrong_key = cls.keys / "TEST-ONLY-wrong-private.pem"
        cls.wrong_public = cls.keys / "TEST-ONLY-wrong-public.pem"
        for private, public in ((cls.key, cls.public), (cls.wrong_key, cls.wrong_public)):
            subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt",
                            "rsa_keygen_bits:3072", "-out", str(private)],
                           check=True, capture_output=True, timeout=60)
            subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)],
                           check=True, capture_output=True, timeout=10)

    @classmethod
    def tearDownClass(cls):
        cls.keys_temporary.cleanup()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="kpbr-release-signature-fixture-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.assets = self.root / "assets"
        self.assets.mkdir()
        self.installer = self.root / "install.sh"
        self.installer.write_bytes(b"#!/bin/sh\n# Test fixture only; never executed.\nexit 0\n")
        (self.assets / PACKAGE).write_bytes(b"test fixture, not an installable IPK\n")
        self.manifest = self.assets / "release-manifest.tsv"
        self.signature = self.assets / "release-manifest.sig"
        self.env = os.environ.copy()
        busybox = shutil.which("busybox")
        if busybox:
            # Also exercise BusyBox awk/core applets, not just its shell parser.
            bin_dir = self.root / "busybox-bin"
            bin_dir.mkdir()
            for applet in ("awk", "wc", "tail", "od", "tr", "sha256sum"):
                (bin_dir / applet).symlink_to(busybox)
            self.env["PATH"] = f"{bin_dir}{os.pathsep}{self.env['PATH']}"
            self.shell = [busybox, "sh"]
        else:
            self.shell = ["sh"]

    def sign(self, **changes):
        options = {
            "assets": self.assets, "installer": self.installer, "key": self.key,
            "public-key": self.public, "repository": REPOSITORY, "channel": "stable",
            "release": RELEASE, "source": "a" * 40, "build": "github-123-1",
        }
        options.update(changes)
        command = [sys.executable, str(SIGNER)]
        for option, value in options.items():
            command.extend([f"--{option}", str(value)])
        return subprocess.run(command, capture_output=True, text=True, timeout=20)

    def prepare(self):
        result = self.sign()
        self.assertEqual(result.returncode, 0, result.stderr)

    def resign(self, payload: bytes):
        self.manifest.write_bytes(payload)
        subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(self.key),
                        "-out", str(self.signature), str(self.manifest)],
                       check=True, capture_output=True, timeout=10)

    def verify(self, **changes):
        options = {
            "manifest": self.manifest, "signature": self.signature, "key": self.public,
            "repository": REPOSITORY, "channel": "stable", "release": RELEASE,
            "kind": "package", "arch": "aarch64", "abi": "3.10", "filename": PACKAGE,
            "localfile": self.assets / PACKAGE,
        }
        options.update(changes)
        return subprocess.run([*self.shell, str(VERIFIER), *map(str, options.values())],
                              capture_output=True, text=True, timeout=10, env=self.env)

    def test_installer_and_full_package_verify_without_stdout(self):
        self.prepare()
        self.assertEqual(self.signature.stat().st_size, 384)
        self.assertNotIn(b"\r", self.manifest.read_bytes())
        for options in ({}, {"kind": "installer", "arch": "any", "abi": "any",
                             "filename": "install.sh", "localfile": self.assets / "install.sh"}):
            with self.subTest(options=options):
                result = self.verify(**options)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, "")

    def test_other_release_channels_use_same_signature_format(self):
        for channel in ("alpha", "beta", "next"):
            with self.subTest(channel=channel):
                result = self.sign(channel=channel, release=f"{channel}-123-1")
                self.assertEqual(result.returncode, 0, result.stderr)
                result = self.verify(channel=channel, release=f"{channel}-123-1")
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_beta_manifest_covers_all_keenetic_profiles(self):
        for arch in ("mips", "mipsel"):
            (self.assets / f"keen-pbr_3.3.1-test_keenetic_{arch}-3.4.ipk").write_bytes(b"test-only IPK\n")
        result = self.sign(channel="beta", release="beta-123-1")
        self.assertEqual(result.returncode, 0, result.stderr)
        for arch, abi in (("aarch64", "3.10"), ("mips", "3.4"), ("mipsel", "3.4")):
            with self.subTest(arch=arch):
                filename = f"keen-pbr_3.3.1-test_keenetic_{arch}-{abi}.ipk"
                result = self.verify(channel="beta", release="beta-123-1", arch=arch, abi=abi,
                                     filename=filename, localfile=self.assets / filename)
                self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotEqual(self.verify(channel="stable", release="beta-123-1").returncode, 0)

    def test_lf_check_does_not_require_full_od_applet(self):
        self.prepare()
        tools = self.root / "restricted-tools"
        tools.mkdir()
        od = tools / "od"
        od.write_text("#!/bin/sh\necho 'od: unsupported on target' >&2\nexit 1\n")
        od.chmod(0o755)
        self.env["PATH"] = f"{tools}{os.pathsep}{self.env['PATH']}"
        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stderr)
        original = self.manifest.read_bytes()
        for last_byte in (b"", b"\r", b"\x00", b"."):
            with self.subTest(last_byte=last_byte):
                self.resign(original[:-1] + last_byte)
                result = self.verify()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("manifest must end with LF", result.stderr)

    def test_changed_manifest_is_rejected_before_inventory_selection(self):
        self.prepare()
        self.manifest.write_bytes(self.manifest.read_bytes().replace(b"github-123-1", b"github-123-2"))
        result = self.verify()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("signature is invalid", result.stderr)

    def test_changed_package_and_installer_are_rejected(self):
        self.prepare()
        (self.assets / PACKAGE).write_bytes(b"different package\n")
        self.assertNotEqual(self.verify().returncode, 0)
        (self.assets / "install.sh").write_bytes(b"#!/bin/sh\n# altered installer\n")
        result = self.verify(kind="installer", arch="any", abi="any", filename="install.sh",
                             localfile=self.assets / "install.sh")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum", result.stderr)

    def test_wrong_public_key_or_context_or_target_is_rejected(self):
        self.prepare()
        for options in ({"key": self.wrong_public}, {"repository": "someone/else"},
                        {"channel": "alpha"}, {"release": "v3.3.0"}, {"arch": "mips"},
                        {"abi": "3.4"}, {"filename": "other.ipk"}, {"kind": "installer"},
                        {"release": "v3.3.1-test\\n"}):
            with self.subTest(options=options):
                self.assertNotEqual(self.verify(**options).returncode, 0)

    def test_signed_duplicate_metadata_or_file_targets_are_rejected(self):
        self.prepare()
        original = self.manifest.read_bytes()
        rows = original.splitlines(keepends=True)
        for payload in (original + rows[-1], b"".join(rows[:2] + [rows[1]] + rows[2:]),
                        original + rows[-1].replace(b"3.3.1-test", b"3.3.2-test")):
            with self.subTest(payload=payload[-90:]):
                self.resign(payload)
                self.assertNotEqual(self.verify().returncode, 0)

    def test_signed_bad_field_schema_paths_and_line_endings_are_rejected(self):
        self.prepare()
        original = self.manifest.read_bytes()
        rows = original.splitlines(keepends=True)
        mutations = [
            original.replace(b"\tinstall.sh", b"\t../install.sh"),
            original.replace(b"\tinstaller\t", b"\tunknown\t"),
            original.replace(b"a" * 40, b"A" * 40, 1),
            original.replace(b"\n", b"\r\n"), original.rstrip(b"\n"),
            original + b"\n", original.replace(b"keen-pbr-release-v1", b"keen-pbr-release-v2"),
            b"".join(rows[:6] + rows[7:]), b"".join(rows[:7]),
            original.replace(b"file\tpackage", b"file\t\x00package"),
        ]
        for index, payload in enumerate(mutations):
            with self.subTest(mutation=index):
                self.resign(payload)
                self.assertNotEqual(self.verify().returncode, 0)

    def test_manifest_size_and_file_count_are_bounded(self):
        self.prepare()
        original = self.manifest.read_bytes()
        self.resign(original + b"#" * 65536 + b"\n")
        result = self.verify()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("size", result.stderr)
        digest = hashlib.sha256(b"fixture").hexdigest()
        extra = "".join(f"file\tpackage\taarch64\t9.{i}\t1\t{digest}\tkeen-pbr_1_keenetic_aarch64-9.{i}.ipk\n"
                        for i in range(31)).encode("ascii")
        self.resign(original + extra)
        self.assertNotEqual(self.verify().returncode, 0)

    def test_missing_or_wrong_sized_signature_is_rejected(self):
        self.prepare()
        self.signature.write_bytes(b"not a signature")
        self.assertNotEqual(self.verify().returncode, 0)
        self.signature.unlink()
        self.assertNotEqual(self.verify().returncode, 0)

    def test_signer_rejects_mismatched_key_without_replacing_assets(self):
        self.prepare()
        originals = {name: (self.assets / name).read_bytes()
                     for name in ("install.sh", "release-manifest.tsv", "release-manifest.sig")}
        result = self.sign(**{"public-key": self.wrong_public})
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("PRIVATE KEY", result.stdout + result.stderr)
        for name, content in originals.items():
            self.assertEqual((self.assets / name).read_bytes(), content)

    def test_signer_rejects_invalid_metadata(self):
        for options in ({"repository": "bad\nrepo/name"}, {"channel": "anything"},
                        {"release": "../latest"}, {"source": "a" * 39},
                        {"build": "b" * 129}):
            with self.subTest(options=options):
                result = self.sign(**options)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.manifest.exists())

    def test_signer_rejects_headless_duplicate_target_and_symlink_packages(self):
        extra = self.assets / "keen-pbr-headless_3.3.1_keenetic_mips-3.4.ipk"
        extra.write_bytes(b"headless fixture")
        self.assertNotEqual(self.sign().returncode, 0)
        extra.unlink()
        extra = self.assets / PACKAGE.replace("3.3.1-test", "3.3.2-test")
        extra.write_bytes(b"duplicate target fixture")
        self.assertNotEqual(self.sign().returncode, 0)
        extra.unlink()
        extra = self.assets / "keen-pbr_3.3.1-test_keenetic_mips-3.4.ipk"
        extra.symlink_to(self.assets / PACKAGE)
        self.assertNotEqual(self.sign().returncode, 0)

    def test_signer_requires_packages_and_limits_file_count(self):
        (self.assets / PACKAGE).unlink()
        self.assertNotEqual(self.sign().returncode, 0)
        for index in range(32):
            (self.assets / f"keen-pbr_1_keenetic_aarch64-9.{index}.ipk").write_bytes(b"fixture")
        self.assertNotEqual(self.sign().returncode, 0)


if __name__ == "__main__":
    unittest.main()

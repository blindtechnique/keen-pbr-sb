from __future__ import annotations

import importlib.util
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "validate-keenetic-ipk.py"
SPEC = importlib.util.spec_from_file_location("validate_keenetic_ipk", SCRIPT)
assert SPEC and SPEC.loader
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


def tar_archive(files: dict[str, tuple[bytes, int]]) -> bytes:
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w:gz") as archive:
        for name, (content, mode) in files.items():
            info = tarfile.TarInfo(f"./{name}")
            info.size = len(content)
            info.mode = mode
            archive.addfile(info, io.BytesIO(content))
    return result.getvalue()


def elf(machine: int = 183, elf_class: int = 2, byte_order: int = 1) -> bytes:
    header = bytearray(64)
    header[:7] = b"\x7fELF" + bytes((elf_class, byte_order, 1))
    header[18:20] = machine.to_bytes(2, "little" if byte_order == 1 else "big")
    return bytes(header)


def ar_archive(members: dict[str, bytes]) -> bytes:
    result = bytearray(b"!<arch>\n")
    for name, content in members.items():
        header = (
            f"{name + '/':<16}{0:<12}{0:<6}{0:<6}{0o100644:<8o}{len(content):<10}`\n"
        ).encode("ascii")
        assert len(header) == 60
        result.extend(header)
        result.extend(content)
        if len(content) % 2:
            result.extend(b"\n")
    return bytes(result)


def make_ipk(
    path: Path, transport_binary: bytes | None = None, outer_tar: bool = False
) -> None:
    executable = 0o755
    config = json.dumps(
        {
            "listen": "127.0.0.1:12122",
            "api_key": "REPLACE_WITH_A_LONG_RANDOM_VALUE",
            "transports": [],
        }
    ).encode()
    files = {
        name: (b"#!/bin/sh\n", executable)
        for name in VALIDATOR.REQUIRED_EXECUTABLES
    }
    files["opt/usr/bin/keen-pbr"] = (elf(), executable)
    files["opt/usr/bin/transport-manager"] = (
        transport_binary if transport_binary is not None else elf(),
        executable,
    )
    files.update(
        {
            "opt/etc/keen-pbr/config.json": (b"{}", 0o600),
            "opt/etc/keen-pbr/transports.json": (config, 0o600),
            "opt/usr/share/keen-pbr/frontend/index.html": (b"<!doctype html>", 0o644),
        }
    )
    conffiles = ("\n".join(sorted(VALIDATOR.REQUIRED_CONFFILES)) + "\n").encode()
    control = tar_archive(
        {
            "conffiles": (conffiles, 0o644),
            "postinst": (
                b"#!/bin/sh\n# REPLACE_WITH_A_LONG_RANDOM_VALUE /dev/urandom\n",
                executable,
            ),
        }
    )
    members = {
        "debian-binary": (b"2.0\n", 0o644),
        "control.tar.gz": (control, 0o644),
        "data.tar.gz": (tar_archive(files), 0o644),
    }
    if outer_tar:
        path.write_bytes(tar_archive(members))
    else:
        path.write_bytes(ar_archive({name: value[0] for name, value in members.items()}))


class ValidateKeeneticIpkTest(unittest.TestCase):
    def test_accepts_complete_aarch64_package(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "keen-pbr.ipk"
            make_ipk(package)
            VALIDATOR.validate(package, "aarch64")

    def test_rejects_wrong_transport_architecture(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "keen-pbr.ipk"
            make_ipk(package, transport_binary=elf(machine=62))
            with self.assertRaisesRegex(VALIDATOR.ValidationError, "incompatible ELF"):
                VALIDATOR.validate(package, "aarch64")

    def test_accepts_entware_tar_ipk(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "keen-pbr.ipk"
            make_ipk(package, outer_tar=True)
            VALIDATOR.validate(package, "aarch64")


if __name__ == "__main__":
    unittest.main()

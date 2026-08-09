from __future__ import annotations

import importlib.util
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "validate-keenetic-ipk.py"
SOURCE_CATALOG = (
    Path(__file__).parents[2]
    / "packages/keenetic/keen-pbr/files/opt/usr/share/keen-pbr/catalog.json"
)
SPEC = importlib.util.spec_from_file_location("validate_keenetic_ipk", SCRIPT)
assert SPEC and SPEC.loader
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


def tar_archive(
    files: dict[str, tuple[bytes, int]], root_name: str | None = None
) -> bytes:
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w:gz") as archive:
        if root_name is not None:
            root = tarfile.TarInfo(root_name)
            root.type = tarfile.DIRTYPE
            root.mode = 0o755
            archive.addfile(root)
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


def bundled_catalog() -> bytes:
    return json.dumps(
        [
            {
                "id": "meta",
                "routingCompanions": [
                    {
                        "id": "meta_whatsapp_ip",
                        "sourcePresetId": "whatsapp-ip-source",
                        "include": "ip_cidrs",
                    }
                ],
            },
            {
                "id": "whatsapp",
                "routingCompanions": [
                    {
                        "id": "whatsapp_ip",
                        "sourcePresetId": "whatsapp-ip-source",
                        "include": "ip_cidrs",
                        "catalogIdentityId": (
                            "meta#routing-companion:meta_whatsapp_ip"
                        ),
                    }
                ],
            },
            {
                "id": "telegram",
                "routingCompanions": [
                    {
                        "id": "telegram_ip",
                        "url": (
                            "https://example.test/geoip-telegram.srs"
                        ),
                    }
                ],
            },
            {
                "id": "whatsapp-ip-source",
                "engines": {"dns": {"subnets": ["31.13.64.0/18"]}},
            },
            {
                "id": "kartina-tv",
                "routingCompanions": [
                    {
                        "id": "kartina_tv_ip",
                        "sourcePresetId": "kartina-tv-ip-source",
                        "include": "ip_cidrs",
                    }
                ],
                "engines": {
                    "dns": {
                        "domains": [
                            "cdn-imaze.com",
                            "iptv-kartina.tv",
                            "kartina.stream",
                            "kartina.tv",
                            "kartina2.com",
                            "kartina2.tv",
                            "streamktv.com",
                        ]
                    }
                },
            },
            {
                "id": "kartina-tv-ip-source",
                "hidden": True,
                "engines": {
                    "dns": {
                        "subnets": [
                            "93.180.240.0/24",
                            "93.180.241.0/24",
                            "93.180.242.0/24",
                            "93.180.243.0/24",
                            "93.180.247.0/24",
                            "185.146.248.0/24",
                            "185.146.249.0/24",
                            "185.146.250.0/24",
                            "185.146.251.0/24",
                        ]
                    }
                },
            },
        ]
    ).encode()


def make_ipk(
    path: Path,
    transport_binary: bytes | None = None,
    outer_tar: bool = False,
    data_root_name: str | None = None,
    control_depends: str = "conntrack, dnsmasq",
    catalog: bytes | None = None,
    binary_commit: str | None = None,
    control_commit: str | None = None,
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
    files["opt/usr/bin/keen-pbr"] = (
        elf() + (binary_commit.encode("ascii") if binary_commit else b""),
        executable,
    )
    files["opt/usr/bin/transport-manager"] = (
        transport_binary if transport_binary is not None else elf(),
        executable,
    )
    files.update(
        {
            "opt/etc/keen-pbr/config.json": (b"{}", 0o600),
            "opt/etc/keen-pbr/transports.json": (config, 0o600),
            "opt/usr/share/keen-pbr/catalog.json": (
                bundled_catalog() if catalog is None else catalog,
                0o644,
            ),
            "opt/usr/share/keen-pbr/frontend/index.html": (b"<!doctype html>", 0o644),
            "opt/usr/share/keen-pbr/nfqws-blobs/SHA256SUMS": (b"", 0o644),
            "opt/usr/share/keen-pbr/nfqws-blobs/ORIGIN_SHA256SUMS": (
                b"",
                0o644,
            ),
            "opt/usr/share/keen-pbr/nfqws-blobs/quic_initial_steamcommunity_com.bin": (
                b"steam",
                0o644,
            ),
            "opt/usr/share/keen-pbr/nfqws-blobs/stun.bin": (b"stun", 0o644),
            "opt/usr/share/keen-pbr/nfqws-blobs/tls_clienthello_4pda_to.bin": (
                b"4pda",
                0o644,
            ),
            "opt/usr/share/keen-pbr/nfqws-blobs/tls_clienthello_max_ru.bin": (
                b"max",
                0o644,
            ),
            "opt/usr/share/keen-pbr/nfqws-strategies/01 safe/nfqws2.conf": (
                b"NFQWS_ARGS=\n",
                0o644,
            ),
            "opt/usr/share/keen-pbr/nfqws-strategies/01 safe/required-blobs.txt": (
                b"stun.bin\n",
                0o644,
            ),
            "opt/usr/share/keen-pbr/nfqws-strategies/02 balanced/nfqws2.conf": (
                b"NFQWS_ARGS=\n",
                0o644,
            ),
            "opt/usr/share/keen-pbr/nfqws-strategies/02 balanced/required-blobs.txt": (
                b"stun.bin\n",
                0o644,
            ),
            "opt/usr/share/keen-pbr/nfqws-strategies/03 max/nfqws2.conf": (
                b"NFQWS_ARGS=\n",
                0o644,
            ),
            "opt/usr/share/keen-pbr/nfqws-strategies/03 max/required-blobs.txt": (
                b"stun.bin\n",
                0o644,
            ),
            "opt/usr/share/keen-pbr/nfqws-strategies/ver9 E max plus/nfqws2.conf": (
                b"NFQWS_ARGS=\n",
                0o644,
            ),
            "opt/usr/share/keen-pbr/nfqws-strategies/ver9 E max plus/required-blobs.txt": (
                b"tls_clienthello_max_ru.bin\n",
                0o644,
            ),
            "opt/usr/share/keen-pbr/nfqws-strategies/ver10 H2 hybrid plus/nfqws2.conf": (
                b"NFQWS_ARGS=\n",
                0o644,
            ),
            "opt/usr/share/keen-pbr/nfqws-strategies/ver10 H2 hybrid plus/required-blobs.txt": (
                b"tls_clienthello_4pda_to.bin\n",
                0o644,
            ),
        }
    )
    conffiles = ("\n".join(sorted(VALIDATOR.REQUIRED_CONFFILES)) + "\n").encode()
    control = tar_archive(
        {
            "control": (
                (
                    "Package: keen-pbr\n"
                    "Version: 1\n"
                    f"Depends: {control_depends}\n"
                    + (
                        "Description: Policy-based routing daemon\n"
                        f" Built from source commit {control_commit}.\n"
                        if control_commit
                        else ""
                    )
                ).encode(),
                0o644,
            ),
            "conffiles": (conffiles, 0o644),
            "postinst": (
                b"#!/bin/sh\n"
                b"# REPLACE_WITH_A_LONG_RANDOM_VALUE /dev/urandom\n"
                b". /opt/usr/lib/keen-pbr/portable-stat.sh\n",
                executable,
            ),
            "prerm": (b"#!/bin/sh\nexit 0\n", executable),
            "postrm": (b"#!/bin/sh\nexit 0\n", executable),
        }
    )
    members = {
        "debian-binary": (b"2.0\n", 0o644),
        "control.tar.gz": (control, 0o644),
        "data.tar.gz": (tar_archive(files, root_name=data_root_name), 0o644),
    }
    if outer_tar:
        path.write_bytes(tar_archive(members))
    else:
        path.write_bytes(ar_archive({name: value[0] for name, value in members.items()}))


class ValidateKeeneticIpkTest(unittest.TestCase):
    def test_source_catalog_contains_required_ip_companions(self) -> None:
        VALIDATOR.validate_bundled_catalog(
            json.loads(SOURCE_CATALOG.read_text(encoding="utf-8"))
        )

    def test_accepts_complete_aarch64_package(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "keen-pbr.ipk"
            make_ipk(package)
            VALIDATOR.validate(package, "aarch64")

    def test_accepts_matching_build_identity_in_binary_and_control(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "keen-pbr.ipk"
            commit = "0123456789ab-dirty"
            make_ipk(
                package,
                binary_commit=commit,
                control_commit=commit,
            )
            VALIDATOR.validate(package, "aarch64", commit)

    def test_rejects_missing_binary_build_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "keen-pbr.ipk"
            commit = "0123456789ab"
            make_ipk(package, control_commit=commit)
            with self.assertRaisesRegex(
                VALIDATOR.ValidationError,
                "binary does not contain the expected build commit",
            ):
                VALIDATOR.validate(package, "aarch64", commit)

    def test_rejects_missing_control_build_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "keen-pbr.ipk"
            commit = "0123456789ab"
            make_ipk(package, binary_commit=commit)
            with self.assertRaisesRegex(
                VALIDATOR.ValidationError,
                "package description does not contain",
            ):
                VALIDATOR.validate(package, "aarch64", commit)

    def test_accepts_standard_data_archive_root_entries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            for index, root_name in enumerate((".", "./")):
                with self.subTest(root_name=root_name):
                    package = Path(directory) / f"keen-pbr-{index}.ipk"
                    make_ipk(package, data_root_name=root_name)
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

    def test_rejects_unexpected_outer_member(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "keen-pbr.ipk"
            make_ipk(package)
            members = VALIDATOR.read_ar(package)
            members["unexpected"] = b"payload"
            package.write_bytes(ar_archive(members))
            with self.assertRaisesRegex(
                VALIDATOR.ValidationError, "unexpected outer IPK members"
            ):
                VALIDATOR.validate(package, "aarch64")

    def test_rejects_non_executable_postinst(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "keen-pbr.ipk"
            make_ipk(package)
            members = VALIDATOR.read_ar(package)
            with tarfile.open(
                fileobj=io.BytesIO(members["control.tar.gz"]), mode="r:*"
            ) as source:
                control_files = {
                    VALIDATOR.normalized(item.name): (
                        source.extractfile(item).read(),
                        0o644 if VALIDATOR.normalized(item.name) == "postinst" else item.mode,
                    )
                    for item in source.getmembers()
                    if item.isfile()
                }
            members["control.tar.gz"] = tar_archive(control_files)
            package.write_bytes(ar_archive(members))
            with self.assertRaisesRegex(
                VALIDATOR.ValidationError, "postinst"
            ):
                VALIDATOR.validate(package, "aarch64")

    def test_rejects_package_without_conntrack_dependency(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "keen-pbr.ipk"
            make_ipk(package, control_depends="dnsmasq, iptables")
            with self.assertRaisesRegex(
                VALIDATOR.ValidationError,
                "missing package dependencies: conntrack",
            ):
                VALIDATOR.validate(package, "aarch64")

    def test_rejects_catalog_without_telegram_ip_companion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "keen-pbr.ipk"
            catalog = json.loads(bundled_catalog())
            telegram = next(item for item in catalog if item["id"] == "telegram")
            telegram["routingCompanions"] = []
            make_ipk(package, catalog=json.dumps(catalog).encode())
            with self.assertRaisesRegex(
                VALIDATOR.ValidationError,
                "telegram is missing companion telegram_ip",
            ):
                VALIDATOR.validate(package, "aarch64")

    def test_rejects_catalog_with_incomplete_kartina_networks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "keen-pbr.ipk"
            catalog = json.loads(bundled_catalog())
            source = next(
                item for item in catalog if item["id"] == "kartina-tv-ip-source"
            )
            source["engines"]["dns"]["subnets"].pop()
            make_ipk(package, catalog=json.dumps(catalog).encode())
            with self.assertRaisesRegex(
                VALIDATOR.ValidationError,
                "Kartina.TV IP source has incomplete CIDRs",
            ):
                VALIDATOR.validate(package, "aarch64")


if __name__ == "__main__":
    unittest.main()

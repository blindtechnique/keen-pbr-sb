#!/usr/bin/env python3
"""Validate the deployable contents of a full keen-pbr Keenetic IPK."""

from __future__ import annotations

import argparse
import io
import json
import stat
import struct
import sys
import tarfile
from pathlib import Path, PurePosixPath


AR_MAGIC = b"!<arch>\n"
ELF_MACHINES = {
    "aarch64": (183, 2, 1),
    "armv7": (40, 1, 1),
    "mips": (8, 1, 2),
    "mipsel": (8, 1, 1),
    "x64": (62, 2, 1),
}
REQUIRED_EXECUTABLES = {
    "opt/usr/bin/keen-pbr",
    "opt/usr/bin/transport-manager",
    "opt/etc/init.d/S79transport-manager",
    "opt/etc/init.d/S80keen-pbr",
    "opt/etc/ndm/netfilter.d/50-keen-pbr-routing.sh",
}
REQUIRED_FILES = REQUIRED_EXECUTABLES | {
    "opt/etc/keen-pbr/config.json",
    "opt/etc/keen-pbr/transports.json",
    "opt/usr/share/keen-pbr/frontend/index.html",
    "opt/usr/share/keen-pbr/nfqws-blobs/ACTIVE_DISCORD_UDP.bin",
    "opt/usr/share/keen-pbr/nfqws-blobs/quic_initial_steamcommunity_com.bin",
    "opt/usr/share/keen-pbr/nfqws-blobs/stun.bin",
    "opt/usr/share/keen-pbr/nfqws-blobs/tls_clienthello_4pda_to.bin",
    "opt/usr/share/keen-pbr/nfqws-blobs/tls_clienthello_max_ru.bin",
    "opt/usr/share/keen-pbr/nfqws-strategies/ver9 E max plus/nfqws2.conf",
    "opt/usr/share/keen-pbr/nfqws-strategies/ver9 E max plus/required-blobs.txt",
    "opt/usr/share/keen-pbr/nfqws-strategies/ver10 H2 hybrid plus/nfqws2.conf",
    "opt/usr/share/keen-pbr/nfqws-strategies/ver10 H2 hybrid plus/required-blobs.txt",
}
REQUIRED_CONFFILES = {
    "/opt/etc/keen-pbr/config.json",
    "/opt/etc/keen-pbr/local.lst",
    "/opt/etc/keen-pbr/dnsmasq-fallback.conf",
    "/opt/etc/keen-pbr/transports.json",
}


class ValidationError(RuntimeError):
    pass


def read_ar(path: Path) -> dict[str, bytes]:
    data = path.read_bytes()
    if not data.startswith(AR_MAGIC):
        raise ValidationError("IPK is not an ar archive")
    offset = len(AR_MAGIC)
    members: dict[str, bytes] = {}
    while offset < len(data):
        header = data[offset : offset + 60]
        if len(header) != 60 or header[58:60] != b"`\n":
            raise ValidationError("malformed ar member header")
        raw_name = header[:16].decode("ascii").strip()
        try:
            size = int(header[48:58].decode("ascii").strip())
        except ValueError as error:
            raise ValidationError("invalid ar member size") from error
        offset += 60
        payload = data[offset : offset + size]
        if len(payload) != size:
            raise ValidationError("truncated ar member")
        offset += size + size % 2
        name = raw_name.rstrip("/")
        members[name] = payload
    return members


def read_ipk(path: Path) -> dict[str, bytes]:
    if path.read_bytes()[: len(AR_MAGIC)] == AR_MAGIC:
        return read_ar(path)
    try:
        with tarfile.open(path, mode="r:*") as archive:
            members: dict[str, bytes] = {}
            for item in archive.getmembers():
                if not item.isfile():
                    continue
                stream = archive.extractfile(item)
                if stream is not None:
                    members[normalized(item.name)] = stream.read()
            return members
    except tarfile.TarError as error:
        raise ValidationError("IPK is neither an ar nor a tar archive") from error


def find_archive(members: dict[str, bytes], prefix: str) -> bytes:
    matches = [content for name, content in members.items() if name.startswith(prefix)]
    if len(matches) != 1:
        raise ValidationError(f"expected exactly one {prefix} archive")
    return matches[0]


def open_tar(content: bytes) -> tarfile.TarFile:
    try:
        return tarfile.open(fileobj=io.BytesIO(content), mode="r:*")
    except tarfile.TarError as error:
        raise ValidationError(f"cannot read compressed tar archive: {error}") from error


def normalized(name: str) -> str:
    return str(PurePosixPath(name.removeprefix("./")))


def validate_elf(member: tarfile.TarInfo, content: bytes, arch: str) -> None:
    if len(content) < 20 or content[:4] != b"\x7fELF":
        raise ValidationError(f"{normalized(member.name)} is not an ELF binary")
    expected_machine, expected_class, expected_data = ELF_MACHINES[arch]
    elf_class, elf_data = content[4], content[5]
    byte_order = "<" if elf_data == 1 else ">"
    machine = struct.unpack(f"{byte_order}H", content[18:20])[0]
    if (machine, elf_class, elf_data) != (
        expected_machine,
        expected_class,
        expected_data,
    ):
        raise ValidationError(
            f"{normalized(member.name)} has incompatible ELF architecture "
            f"(machine={machine}, class={elf_class}, data={elf_data})"
        )


def validate(path: Path, arch: str) -> None:
    members = read_ipk(path)
    if members.get("debian-binary", b"").strip() != b"2.0":
        raise ValidationError("missing or unsupported debian-binary member")

    with open_tar(find_archive(members, "data.tar")) as data_tar:
        entries = {normalized(item.name): item for item in data_tar.getmembers()}
        missing = sorted(REQUIRED_FILES - entries.keys())
        if missing:
            raise ValidationError("missing package files: " + ", ".join(missing))
        for name in REQUIRED_EXECUTABLES:
            if not entries[name].isfile() or not entries[name].mode & stat.S_IXUSR:
                raise ValidationError(f"{name} is not executable")

        for binary in ("opt/usr/bin/keen-pbr", "opt/usr/bin/transport-manager"):
            stream = data_tar.extractfile(entries[binary])
            if stream is None:
                raise ValidationError(f"cannot read {binary}")
            validate_elf(entries[binary], stream.read(64), arch)

        config_stream = data_tar.extractfile(entries["opt/etc/keen-pbr/transports.json"])
        if config_stream is None:
            raise ValidationError("cannot read transports.json")
        config = json.load(config_stream)
        if config.get("listen") != "127.0.0.1:12122":
            raise ValidationError("transport manager must listen on 127.0.0.1:12122")
        if config.get("api_key") != "REPLACE_WITH_A_LONG_RANDOM_VALUE":
            raise ValidationError("transport API key placeholder is missing")

    with open_tar(find_archive(members, "control.tar")) as control_tar:
        entries = {normalized(item.name): item for item in control_tar.getmembers()}
        if "postinst" not in entries or "conffiles" not in entries:
            raise ValidationError("control archive must contain postinst and conffiles")
        conffiles_stream = control_tar.extractfile(entries["conffiles"])
        postinst_stream = control_tar.extractfile(entries["postinst"])
        if conffiles_stream is None or postinst_stream is None:
            raise ValidationError("cannot read package control files")
        conffiles = set(conffiles_stream.read().decode().splitlines())
        missing_conffiles = sorted(REQUIRED_CONFFILES - conffiles)
        if missing_conffiles:
            raise ValidationError(
                "missing conffiles entries: " + ", ".join(missing_conffiles)
            )
        postinst = postinst_stream.read().decode()
        if "REPLACE_WITH_A_LONG_RANDOM_VALUE" not in postinst or "/dev/urandom" not in postinst:
            raise ValidationError("postinst does not initialize the transport API key")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("ipk", type=Path)
    parser.add_argument("--arch", choices=sorted(ELF_MACHINES), required=True)
    args = parser.parse_args()
    try:
        validate(args.ipk, args.arch)
    except (OSError, ValueError, ValidationError) as error:
        print(f"IPK validation failed: {error}", file=sys.stderr)
        return 1
    print(f"IPK validation passed: {args.ipk} ({args.arch})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

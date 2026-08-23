#!/usr/bin/env python3
"""Validate the deployable contents of a full keen-pbr Keenetic IPK."""

from __future__ import annotations

import argparse
import io
import json
import re
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
    "opt/etc/init.d/S52keen-pbr-ssh-guard",
    "opt/etc/ndm/netfilter.d/50-keen-pbr-routing.sh",
    "opt/usr/lib/keen-pbr/self-update.sh",
    "opt/usr/lib/keen-pbr/rescue-update.sh",
    "opt/usr/lib/keen-pbr/rescue-startup-guard.sh",
    "opt/usr/lib/keen-pbr/ssh-boot-guard.sh",
    "opt/usr/lib/keen-pbr/update-lock.sh",
    "opt/usr/lib/keen-pbr/portable-stat.sh",
}
REQUIRED_FILES = REQUIRED_EXECUTABLES | {
    "opt/etc/keen-pbr/config.json",
    "opt/etc/keen-pbr/transports.json",
    "opt/usr/share/keen-pbr/catalog.json",
    "opt/usr/share/keen-pbr/frontend/index.html",
    "opt/usr/share/keen-pbr/nfqws-blobs/SHA256SUMS",
    "opt/usr/share/keen-pbr/nfqws-blobs/ORIGIN_SHA256SUMS",
    "opt/usr/share/keen-pbr/nfqws-blobs/quic_initial_steamcommunity_com.bin",
    "opt/usr/share/keen-pbr/nfqws-blobs/stun.bin",
    "opt/usr/share/keen-pbr/nfqws-blobs/tls_clienthello_4pda_to.bin",
    "opt/usr/share/keen-pbr/nfqws-blobs/tls_clienthello_max_ru.bin",
    "opt/usr/share/keen-pbr/nfqws-lua/rotator-telemetry.lua",
    "opt/usr/share/keen-pbr/nfqws-strategies/01 safe/nfqws2.conf",
    "opt/usr/share/keen-pbr/nfqws-strategies/01 safe/required-blobs.txt",
    "opt/usr/share/keen-pbr/nfqws-strategies/02 balanced/nfqws2.conf",
    "opt/usr/share/keen-pbr/nfqws-strategies/02 balanced/required-blobs.txt",
    "opt/usr/share/keen-pbr/nfqws-strategies/03 max/nfqws2.conf",
    "opt/usr/share/keen-pbr/nfqws-strategies/03 max/required-blobs.txt",
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
REQUIRED_CONTROL_FILES = {
    "control",
    "conffiles",
    "postinst",
    "prerm",
    "postrm",
}
REQUIRED_CONTROL_EXECUTABLES = {
    "postinst",
    "prerm",
    "postrm",
}
REQUIRED_PACKAGE_DEPENDENCIES = {
    "conntrack",
}
EXPECTED_OUTER_MEMBERS = {
    "debian-binary",
    "control.tar.gz",
    "data.tar.gz",
}


class ValidationError(RuntimeError):
    pass


def validate_bundled_catalog(catalog: object) -> None:
    if not isinstance(catalog, list):
        raise ValidationError("bundled catalog must be a JSON array")

    presets: dict[str, dict[str, object]] = {}
    for item in catalog:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            raise ValidationError("bundled catalog contains a preset without an id")
        preset_id = item["id"]
        if preset_id in presets:
            raise ValidationError(f"bundled catalog contains duplicate preset: {preset_id}")
        presets[preset_id] = item

    def companion(parent_id: str, companion_id: str) -> dict[str, object]:
        parent = presets.get(parent_id)
        if parent is None:
            raise ValidationError(f"bundled catalog is missing preset: {parent_id}")
        companions = parent.get("routingCompanions")
        if not isinstance(companions, list):
            raise ValidationError(
                f"bundled catalog preset {parent_id} has no routing companions"
            )
        match = next(
            (
                value
                for value in companions
                if isinstance(value, dict) and value.get("id") == companion_id
            ),
            None,
        )
        if match is None:
            raise ValidationError(
                f"bundled catalog preset {parent_id} is missing companion {companion_id}"
            )
        return match

    meta = companion("meta", "meta_whatsapp_ip")
    whatsapp = companion("whatsapp", "whatsapp_ip")
    telegram = companion("telegram", "telegram_ip")
    kartina = companion("kartina-tv", "kartina_tv_ip")
    if meta.get("sourcePresetId") != "whatsapp-ip-source" or meta.get("include") != "ip_cidrs":
        raise ValidationError("Meta IP companion does not use the bundled WhatsApp CIDRs")
    if (
        whatsapp.get("sourcePresetId") != "whatsapp-ip-source"
        or whatsapp.get("include") != "ip_cidrs"
    ):
        raise ValidationError("WhatsApp IP companion does not use the bundled WhatsApp CIDRs")
    if whatsapp.get("catalogIdentityId") != "meta#routing-companion:meta_whatsapp_ip":
        raise ValidationError("Meta and WhatsApp IP companions do not share one identity")
    telegram_url = telegram.get("url")
    if not isinstance(telegram_url, str) or "geoip-telegram.srs" not in telegram_url:
        raise ValidationError("Telegram IP companion does not use the GeoIP rule set")
    if (
        kartina.get("sourcePresetId") != "kartina-tv-ip-source"
        or kartina.get("include") != "ip_cidrs"
    ):
        raise ValidationError("Kartina.TV IP companion does not use its bundled CIDRs")

    source = presets.get("whatsapp-ip-source")
    engines = source.get("engines") if source else None
    dns = engines.get("dns") if isinstance(engines, dict) else None
    subnets = dns.get("subnets") if isinstance(dns, dict) else None
    if not isinstance(subnets, list) or not subnets:
        raise ValidationError("bundled WhatsApp IP source contains no CIDRs")

    kartina_parent = presets["kartina-tv"]
    kartina_engines = kartina_parent.get("engines")
    kartina_dns = (
        kartina_engines.get("dns") if isinstance(kartina_engines, dict) else None
    )
    kartina_domains = (
        kartina_dns.get("domains") if isinstance(kartina_dns, dict) else None
    )
    required_kartina_domains = {
        "cdn-imaze.com",
        "iptv-kartina.tv",
        "kartina.stream",
        "kartina.tv",
        "kartina2.com",
        "kartina2.tv",
        "streamktv.com",
    }
    if (
        not isinstance(kartina_domains, list)
        or set(kartina_domains) != required_kartina_domains
    ):
        raise ValidationError("bundled Kartina.TV preset has incomplete domains")

    kartina_source = presets.get("kartina-tv-ip-source")
    if not isinstance(kartina_source, dict):
        raise ValidationError("bundled catalog is missing Kartina.TV IP source")
    kartina_source_engines = kartina_source.get("engines")
    kartina_source_dns = (
        kartina_source_engines.get("dns")
        if isinstance(kartina_source_engines, dict)
        else None
    )
    kartina_subnets = (
        kartina_source_dns.get("subnets")
        if isinstance(kartina_source_dns, dict)
        else None
    )
    required_kartina_subnets = {
        "93.180.240.0/24",
        "93.180.241.0/24",
        "93.180.242.0/24",
        "93.180.243.0/24",
        "93.180.247.0/24",
        "185.146.248.0/24",
        "185.146.249.0/24",
        "185.146.250.0/24",
        "185.146.251.0/24",
    }
    if (
        not isinstance(kartina_subnets, list)
        or set(kartina_subnets) != required_kartina_subnets
    ):
        raise ValidationError("bundled Kartina.TV IP source has incomplete CIDRs")
    if not kartina_source.get("hidden", False):
        raise ValidationError("bundled Kartina.TV IP source must stay hidden")


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
        if name in members:
            raise ValidationError(f"duplicate ar member: {name}")
        members[name] = payload
    return members


def validated_member_name(name: str, archive_name: str) -> str | None:
    if "\\" in name:
        raise ValidationError(f"{archive_name} contains unsafe member path: {name}")
    if name in (".", "./"):
        return None
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise ValidationError(f"{archive_name} contains unsafe member path: {name}")
    parts = tuple(part for part in path.parts if part not in ("", "."))
    if not parts:
        raise ValidationError(f"{archive_name} contains an empty member path")
    return "/".join(parts)


def indexed_tar_members(
    archive: tarfile.TarFile, archive_name: str
) -> dict[str, tarfile.TarInfo]:
    entries: dict[str, tarfile.TarInfo] = {}
    for item in archive.getmembers():
        name = validated_member_name(item.name, archive_name)
        if name is None:
            if not item.isdir():
                raise ValidationError(
                    f"{archive_name} contains non-directory root member"
                )
            continue
        if name in entries:
            raise ValidationError(f"{archive_name} contains duplicate member: {name}")
        entries[name] = item
    return entries


def read_ipk(path: Path) -> dict[str, bytes]:
    if path.read_bytes()[: len(AR_MAGIC)] == AR_MAGIC:
        return read_ar(path)
    try:
        with tarfile.open(path, mode="r:*") as archive:
            members: dict[str, bytes] = {}
            for item in archive.getmembers():
                name = validated_member_name(item.name, "outer IPK archive")
                if name is None:
                    if not item.isdir():
                        raise ValidationError(
                            "outer IPK archive contains non-directory root member"
                        )
                    continue
                if not item.isfile():
                    continue
                stream = archive.extractfile(item)
                if stream is not None:
                    if name in members:
                        raise ValidationError(
                            f"outer IPK archive contains duplicate member: {name}"
                        )
                    members[name] = stream.read()
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


def validate(path: Path, arch: str, expected_commit: str | None = None) -> None:
    if expected_commit is not None and re.fullmatch(
        r"(?:unknown|[0-9a-f]{12,64}(?:-dirty)?)", expected_commit
    ) is None:
        raise ValidationError("invalid expected build commit identity")

    members = read_ipk(path)
    if set(members) != EXPECTED_OUTER_MEMBERS:
        raise ValidationError(
            "unexpected outer IPK members: "
            + ", ".join(sorted(set(members) ^ EXPECTED_OUTER_MEMBERS))
        )
    if members.get("debian-binary") != b"2.0\n":
        raise ValidationError("missing or unsupported debian-binary member")

    with open_tar(find_archive(members, "data.tar")) as data_tar:
        entries = indexed_tar_members(data_tar, "data archive")
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
            binary_content = stream.read()
            validate_elf(entries[binary], binary_content[:64], arch)
            if (
                expected_commit is not None
                and binary == "opt/usr/bin/keen-pbr"
                and expected_commit.encode("ascii") not in binary_content
            ):
                raise ValidationError(
                    "keen-pbr binary does not contain the expected build commit"
                )

        config_stream = data_tar.extractfile(entries["opt/etc/keen-pbr/transports.json"])
        if config_stream is None:
            raise ValidationError("cannot read transports.json")
        config = json.load(config_stream)
        if config.get("listen") != "127.0.0.1:12122":
            raise ValidationError("transport manager must listen on 127.0.0.1:12122")
        if config.get("api_key") != "REPLACE_WITH_A_LONG_RANDOM_VALUE":
            raise ValidationError("transport API key placeholder is missing")

        catalog_stream = data_tar.extractfile(
            entries["opt/usr/share/keen-pbr/catalog.json"]
        )
        if catalog_stream is None:
            raise ValidationError("cannot read bundled catalog.json")
        validate_bundled_catalog(json.load(catalog_stream))

    with open_tar(find_archive(members, "control.tar")) as control_tar:
        entries = indexed_tar_members(control_tar, "control archive")
        missing_control = sorted(REQUIRED_CONTROL_FILES - entries.keys())
        if missing_control:
            raise ValidationError(
                "control archive is missing files: " + ", ".join(missing_control)
            )
        for name in REQUIRED_CONTROL_FILES:
            if not entries[name].isfile():
                raise ValidationError(f"control archive member is not a file: {name}")
            if entries[name].uid != 0 or entries[name].gid != 0:
                raise ValidationError(f"control archive member is not root-owned: {name}")
        for name in REQUIRED_CONTROL_EXECUTABLES:
            if not entries[name].mode & stat.S_IXUSR:
                raise ValidationError(f"control script is not executable: {name}")
        conffiles_stream = control_tar.extractfile(entries["conffiles"])
        control_stream = control_tar.extractfile(entries["control"])
        postinst_stream = control_tar.extractfile(entries["postinst"])
        if (
            conffiles_stream is None
            or control_stream is None
            or postinst_stream is None
        ):
            raise ValidationError("cannot read package control files")
        control = control_stream.read().decode()
        if expected_commit is not None and (
            f"Built from source commit {expected_commit}." not in control
        ):
            raise ValidationError(
                "package description does not contain the expected build commit"
            )
        depends_match = re.search(
            r"^Depends:\s*(.*(?:\n[ \t].*)*)$",
            control,
            flags=re.MULTILINE,
        )
        dependencies: set[str] = set()
        if depends_match:
            for value in depends_match.group(1).replace("\n", " ").split(","):
                name = value.strip().split(maxsplit=1)[0]
                if name:
                    dependencies.add(name)
        missing_dependencies = sorted(
            REQUIRED_PACKAGE_DEPENDENCIES - dependencies
        )
        if missing_dependencies:
            raise ValidationError(
                "missing package dependencies: "
                + ", ".join(missing_dependencies)
            )
        conffiles = set(conffiles_stream.read().decode().splitlines())
        missing_conffiles = sorted(REQUIRED_CONFFILES - conffiles)
        if missing_conffiles:
            raise ValidationError(
                "missing conffiles entries: " + ", ".join(missing_conffiles)
            )
        postinst = postinst_stream.read().decode()
        if "REPLACE_WITH_A_LONG_RANDOM_VALUE" not in postinst or "/dev/urandom" not in postinst:
            raise ValidationError("postinst does not initialize the transport API key")
        if "stat -c" in postinst:
            raise ValidationError("postinst requires GNU stat instead of the BusyBox-compatible helper")
        if "portable-stat.sh" not in postinst:
            raise ValidationError("postinst does not load portable metadata support")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("ipk", type=Path)
    parser.add_argument("--arch", choices=sorted(ELF_MACHINES), required=True)
    parser.add_argument("--expected-commit")
    args = parser.parse_args()
    try:
        validate(args.ipk, args.arch, args.expected_commit)
    except (OSError, ValueError, ValidationError) as error:
        print(f"IPK validation failed: {error}", file=sys.stderr)
        return 1
    print(f"IPK validation passed: {args.ipk} ({args.arch})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

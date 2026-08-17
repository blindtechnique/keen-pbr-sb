#!/usr/bin/env python3
"""Roadmap: "P0. Ввести единый invariant gate для пресетов и бинарных assets
nfqws2."

Проверяет инварианты из пункта:

  1. уникальность содержимого поставляемых блобов (SHA-256);
  2. SHA-256 manifest — есть и совпадает;
  3. каждая внешняя зависимость объявлена в `required-blobs`;
  4. запрет `--new` внутри NFQWS_BASE_ARGS, NFQWS_ARGS, NFQWS_ARGS_QUIC,
     NFQWS_ARGS_UDP и NFQWS_ARGS_IPSET;
  5. покрытие портов фильтров списками TCP_PORTS / UDP_PORTS;
  6. единая явная политика IPV6_ENABLED между профилями;
  7. реальная глубина пула каждого протокола либо точный opt-out;
  8. отсутствие известных диалоговых фрагментов и опечаток в именах.

Гейт не исправляет файлы сам. Он сверяет package manifest, независимый origin
manifest, pinned provenance/license, CRLF-критичный HTTP packet fixture и
byte-for-byte вывод генератора. Подтверждённый legacy-долг живёт в
`nfqws-assets.known-issues`: новое расхождение падает, а список не может тихо
расти.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

DEFAULT_REPO_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = DEFAULT_REPO_ROOT
SHARE = Path()
BLOBS = Path()
STRATEGIES = Path()
MANIFEST = Path()
ORIGIN_MANIFEST = Path()
REQUIRED_BLOBS = Path()
KNOWN_ISSUES = Path()
GENERATOR = Path()
SOURCE_PROVENANCE = Path()
SOURCE_LICENSE = Path()


def configure_repo_root(repo_root: Path) -> None:
    """Select the tree explicitly; production never consults ambient env."""
    global REPO_ROOT, SHARE, BLOBS, STRATEGIES, MANIFEST, ORIGIN_MANIFEST
    global REQUIRED_BLOBS, KNOWN_ISSUES, GENERATOR, SOURCE_PROVENANCE
    global SOURCE_LICENSE
    REPO_ROOT = repo_root.resolve()
    SHARE = (
        REPO_ROOT
        / "packages/keenetic/keen-pbr/files/opt/usr/share/keen-pbr"
    )
    BLOBS = SHARE / "nfqws-blobs"
    STRATEGIES = SHARE / "nfqws-strategies"
    MANIFEST = BLOBS / "SHA256SUMS"
    ORIGIN_MANIFEST = BLOBS / "ORIGIN_SHA256SUMS"
    REQUIRED_BLOBS = SHARE / "nfqws-required-blobs"
    KNOWN_ISSUES = REPO_ROOT / "build_scripts" / "nfqws-assets.known-issues"
    GENERATOR = REPO_ROOT / "build_scripts" / "build-nfqws-strategies.py"
    SOURCE_PROVENANCE = BLOBS / "third_party" / "z2k" / "SOURCE.md"
    SOURCE_LICENSE = BLOBS / "third_party" / "z2k" / "LICENSE.MIT"


configure_repo_root(DEFAULT_REPO_ROOT)

FORBIDDEN_NEW_IN = (
    "NFQWS_BASE_ARGS",
    "NFQWS_ARGS",
    "NFQWS_ARGS_QUIC",
    "NFQWS_ARGS_UDP",
    "NFQWS_ARGS_IPSET",
)

PORT_FILTER_VARS = FORBIDDEN_NEW_IN + ("NFQWS_ARGS_CUSTOM",)

STRATEGY_POOLS = (
    ("tcp", "NFQWS_ARGS", "ROTATION_UNAVAILABLE_TCP"),
    ("quic", "NFQWS_ARGS_QUIC", "ROTATION_UNAVAILABLE_QUIC"),
    ("udp", "NFQWS_ARGS_UDP", "ROTATION_UNAVAILABLE_UDP"),
)

MIN_POOL_DEPTH = 2

GENERATED_PROFILES = ("01 safe", "02 balanced", "03 max")
Z2K_SOURCE_COMMIT = "ee2d04a5554dea26bbded45416e13e590bb71c6c"
HTTP_IANA_SHA256 = (
    "3e4fb49b1323ddf2f8e691b1cbe804207b4e849711d76f79ebf2b54247a9285e"
)

# Список намеренно узкий. Каждому точному фрагменту нужна своя waiver-строка,
# поэтому новый фрагмент в уже известном профиле всё равно уронит gate.
DIALOGUE_MARKERS = (
    "your previous",
    "your file",
    "rollback baseline",
    "as an ai",
    "i apologize",
)

NAME_TYPOS = {
    "aggresive": "aggressive",
    "agressive": "aggressive",
    "recieve": "receive",
    "seperate": "separate",
}

problems: list[str] = []


def fail(message: str) -> None:
    problems.append(message)


def parse_shell_assignments(text: str) -> dict[str, str]:
    """Достаёт NAME="..." с многострочными значениями.

    Строки-комментарии внутри значения отбрасываем: в этих конфигах комментарии
    живут прямо внутри кавычек, и без их удаления пример из комментария
    (`NFQWS_ARGS_CUSTOM="... --new ..."`) выглядел бы как настоящий аргумент.
    """
    values: dict[str, str] = {}
    # Значение бывает и без кавычек: списки портов записаны как
    # `TCP_PORTS=80,443,...`. Первая версия ловила только кавычки, поэтому
    # разрешённые порты выходили пустыми и «непокрытым» оказывался каждый порт.
    pattern = re.compile(r'^([A-Z_][A-Z0-9_]*)=("?)', re.MULTILINE)
    for match in pattern.finditer(text):
        name = match.group(1)
        if match.group(2):
            end = text.find('"', match.end())
            if end == -1:
                continue
            raw = text[match.end() : end]
        else:
            end = text.find("\n", match.end())
            raw = text[match.end() : end if end != -1 else len(text)]
        cleaned = "\n".join(
            line for line in raw.splitlines() if not line.strip().startswith("#")
        )
        values[name] = cleaned
    return values


def load_known_issues() -> set[str]:
    if not KNOWN_ISSUES.exists():
        return set()
    issues = set()
    for raw in KNOWN_ISSUES.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            issues.add(line)
    return issues


def parse_checksum_manifest(path: Path, label: str) -> dict[str, str]:
    if not path.exists():
        fail(f"нет {label} {path.relative_to(REPO_ROOT)}")
        return {}
    result: dict[str, str] = {}
    for line_number, raw in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not raw:
            continue
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+)", raw)
        if match is None:
            fail(f"{label}:{line_number}: неверный формат строки")
            continue
        digest, name = match.groups()
        if name in result:
            fail(f"{label}:{line_number}: повтор имени {name}")
            continue
        result[name] = digest
    return result


def check_generated_profile_parity() -> None:
    """The generator is the byte-for-byte source of the three new profiles."""
    if not GENERATOR.is_file():
        fail(f"нет генератора {GENERATOR.relative_to(REPO_ROOT)}")
        return
    with tempfile.TemporaryDirectory(prefix="keen-pbr-nfqws-generator-") as raw:
        generated = Path(raw)
        result = subprocess.run(
            [sys.executable, str(GENERATOR), str(generated)],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        if result.returncode != 0:
            fail(
                "генератор новых nfqws-профилей завершился с ошибкой: "
                + (result.stderr.strip() or result.stdout.strip())
            )
            return
        for profile in GENERATED_PROFILES:
            checked_in = STRATEGIES / profile
            rendered = generated / profile
            for filename in ("nfqws2.conf", "required-blobs.txt"):
                expected = checked_in / filename
                actual = rendered / filename
                if not expected.is_file():
                    fail(f"{profile}: нет checked-in {filename}")
                    continue
                if not actual.is_file() or actual.read_bytes() != expected.read_bytes():
                    fail(
                        f"{profile}/{filename}: checked-in bytes расходятся с "
                        f"{GENERATOR.name}"
                    )


def issue_key(kind: str, *parts: str) -> str:
    """Stable, exact waiver identity.

    A waiver records the observed shape, not merely its broad category. That
    prevents an old `shallow-pool profile quic` entry from hiding a newly
    changed pool or a second dialogue fragment.
    """
    values = (kind, *parts)
    if any("|" in value or "\n" in value for value in values):
        raise ValueError("nfqws issue-key fields must not contain '|' or newlines")
    return "|".join(values)


def is_waived(key: str, known: set[str], used: set[str]) -> bool:
    if key not in known:
        return False
    used.add(key)
    return True


def expand_ports(spec: str, range_separators: str) -> set[int]:
    ports: set[int] = set()
    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue
        separator = next((c for c in range_separators if c in item), None)
        if separator:
            low, _, high = item.partition(separator)
            try:
                ports.update(range(int(low), int(high) + 1))
            except ValueError:
                return set()
        else:
            try:
                ports.add(int(item))
            except ValueError:
                return set()
    return ports


def pool_shape(value: str) -> tuple[bool, int, int, str]:
    """Return circular flag, ids, distinct real bodies and semantic digest.

    Strategy numbers outside a `--lua-desync=...` token prove nothing. Multiple
    IDs with byte-identical action bodies are also one real choice, not a pool.
    The digest is based on shell tokens rather than formatting whitespace and
    makes a waiver invalid as soon as the assignment semantics change.
    """
    try:
        tokens = shlex.split(value, comments=False, posix=True)
    except ValueError:
        # The structural validator owns the detailed quote diagnostic. For this
        # gate an unparseable value is a unique non-working shape, never a pool.
        tokens = ["<unparseable>", value]

    circular = any(
        token == "--lua-desync=circular"
        or token.startswith("--lua-desync=circular:")
        for token in tokens
    )
    actions: dict[int, list[str]] = {}
    for token in tokens:
        if not token.startswith("--lua-desync="):
            continue
        if token == "--lua-desync=circular" or token.startswith(
            "--lua-desync=circular:"
        ):
            continue
        match = re.search(r"(?<=[,:])strategy=(\d+)(?=[:,]|$)", token)
        if match is None:
            continue
        strategy_id = int(match.group(1))
        normalized = token[: match.start()] + token[match.end() :]
        actions.setdefault(strategy_id, []).append(normalized)

    bodies = {tuple(parts) for parts in actions.values()}
    semantic = "\0".join(tokens).encode("utf-8")
    digest = hashlib.sha256(semantic).hexdigest()
    return circular, len(actions), len(bodies), digest


def check_ipv6_policy(
    profiles: dict[str, dict[str, str]],
    known: set[str],
    used: set[str],
) -> None:
    """Require a complete policy and exact waivers for current exceptions."""
    values: dict[str, list[str]] = {"0": [], "1": []}
    for label, assignments in sorted(profiles.items()):
        raw = assignments.get("IPV6_ENABLED")
        value = raw.strip() if raw is not None else ""
        if value not in values:
            fail(
                f"{label}: IPV6_ENABLED должен быть явно равен 0 или 1, "
                f"получено {value!r}"
            )
            continue
        values[value].append(label)

    counts = {value: len(labels) for value, labels in values.items()}
    if counts["0"] == counts["1"]:
        fail(
            "IPV6_ENABLED не имеет единой majority-политики: "
            f"0 у {counts['0']} профилей, 1 у {counts['1']}"
        )
        return

    baseline = "0" if counts["0"] > counts["1"] else "1"
    other = "1" if baseline == "0" else "0"
    for label in sorted(values[other]):
        key = issue_key(
            "ipv6-exception",
            label,
            f"value={other}",
            f"baseline={baseline}",
        )
        if is_waived(key, known, used):
            continue
        fail(
            f"{label}: IPV6_ENABLED={other}, majority={baseline}; "
            "переключение профиля молча изменит IPv6; "
            f"waiver key: {key}"
        )


def main() -> int:
    problems.clear()
    known = load_known_issues()
    used_known: set[str] = set()

    if not BLOBS.is_dir() or not STRATEGIES.is_dir():
        print(f"ERROR: asset directories not found under {SHARE}")
        return 2

    shipped = sorted(p for p in BLOBS.iterdir() if p.suffix == ".bin")
    if not shipped:
        print("ERROR: no shipped blobs found; the gate is looking in the wrong place.")
        return 2

    digests: dict[str, list[str]] = {}
    actual_digests: dict[str, str] = {}
    for blob in shipped:
        digest = hashlib.sha256(blob.read_bytes()).hexdigest()
        actual_digests[blob.name] = digest
        digests.setdefault(digest, []).append(blob.name)

    # 1. Уникальность содержимого.
    for digest, names in sorted(digests.items()):
        if len(names) > 1:
            key = issue_key("duplicate", digest, *sorted(names))
            if is_waived(key, known, used_known):
                continue
            fail(
                f"дубль содержимого: {', '.join(sorted(names))} "
                f"(sha256 {digest[:16]}…); waiver key: {key}"
            )

    # 2. Манифест.
    expected = "".join(
        f"{hashlib.sha256(b.read_bytes()).hexdigest()}  {b.name}\n" for b in shipped
    )
    if not MANIFEST.exists():
        fail(f"нет манифеста {MANIFEST.relative_to(REPO_ROOT)}; создайте его")
    elif MANIFEST.read_text(encoding="utf-8") != expected:
        fail(
            f"манифест {MANIFEST.relative_to(REPO_ROOT)} расходится с файлами; "
            "пересоберите его"
        )

    # The regular manifest describes the package. The origin manifest is an
    # independent review pin: regenerating SHA256SUMS from accidentally
    # converted bytes must not make that conversion look valid.
    origin = parse_checksum_manifest(ORIGIN_MANIFEST, "origin manifest")
    if set(origin) != set(actual_digests):
        missing = sorted(set(actual_digests) - set(origin))
        extra = sorted(set(origin) - set(actual_digests))
        fail(
            "origin manifest не покрывает пакет точно: "
            f"missing={missing}, extra={extra}"
        )
    for name in sorted(set(origin) & set(actual_digests)):
        if origin[name] != actual_digests[name]:
            fail(
                f"{name}: SHA-256 {actual_digests[name]} расходится с "
                f"origin pin {origin[name]}"
            )

    if not SOURCE_LICENSE.is_file():
        fail(f"нет лицензии источника {SOURCE_LICENSE.relative_to(REPO_ROOT)}")
    if not SOURCE_PROVENANCE.is_file():
        fail(
            f"нет описания происхождения "
            f"{SOURCE_PROVENANCE.relative_to(REPO_ROOT)}"
        )
    elif Z2K_SOURCE_COMMIT not in SOURCE_PROVENANCE.read_text(encoding="utf-8"):
        fail("описание происхождения не содержит pinned z2k commit")

    http_fixture = BLOBS / "http_iana_org.bin"
    if http_fixture.exists():
        payload = http_fixture.read_bytes()
        digest = hashlib.sha256(payload).hexdigest()
        bare_lf = b"\n" in payload.replace(b"\r\n", b"")
        if digest != HTTP_IANA_SHA256 or payload.count(b"\r\n") != 9 or bare_lf:
            fail(
                "http_iana_org.bin повреждён нормализацией строк: нужны "
                "427 bytes, 9 CRLF, 0 bare LF и pinned SHA-256 "
                f"{HTTP_IANA_SHA256}"
            )

    if GENERATOR.exists() or any(
        (STRATEGIES / profile).exists() for profile in GENERATED_PROFILES
    ):
        check_generated_profile_parity()

    # 3-5. Разбор стратегий.
    declared_external = set()
    if REQUIRED_BLOBS.exists():
        for raw in REQUIRED_BLOBS.read_text(encoding="utf-8").splitlines():
            line = raw.split("#", 1)[0].strip()
            if line:
                declared_external.add(line)

    shipped_names = {b.name for b in shipped}
    strategies = sorted(STRATEGIES.glob("*/nfqws2.conf"))
    if not strategies:
        print("ERROR: no strategy configs found.")
        return 2

    profiles: dict[str, dict[str, str]] = {}

    for conf in strategies:
        label = conf.parent.name
        text = conf.read_text(encoding="utf-8")
        values = parse_shell_assignments(text)
        profiles[label] = values

        profile_manifest = conf.parent / "required-blobs.txt"
        if label in GENERATED_PROFILES and not profile_manifest.is_file():
            fail(f"{label}: нет required-blobs.txt")
        if profile_manifest.is_file():
            manifest_entries = [
                line.strip()
                for line in profile_manifest.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            invalid_entries = [
                name
                for name in manifest_entries
                if Path(name).name != name
                or re.fullmatch(r"[A-Za-z0-9_.-]+\.bin", name) is None
            ]
            if invalid_entries:
                fail(
                    f"{label}: небезопасные имена в required-blobs.txt: "
                    f"{invalid_entries}"
                )
            if manifest_entries != sorted(set(manifest_entries)):
                fail(
                    f"{label}: required-blobs.txt должен быть отсортирован "
                    "и не содержать дублей"
                )
            referenced = set(re.findall(r"[A-Za-z0-9_.-]+\.bin", text))
            expected_required = sorted(
                name for name in referenced if name in shipped_names
            )
            if manifest_entries != expected_required:
                fail(
                    f"{label}: required-blobs.txt расходится с конфигом; "
                    f"expected={expected_required}, actual={manifest_entries}"
                )

        # 7. A pool either has at least two distinct circular choices or says
        # exactly `=1` that rotation is unavailable. Garbage values cannot
        # silently disable the invariant.
        for proto, variable, opt_out in STRATEGY_POOLS:
            raw_opt_out = values.get(opt_out, "").strip()
            if raw_opt_out not in ("", "0", "1"):
                fail(
                    f"{label}: {opt_out} должен быть 0 или 1, "
                    f"получено {raw_opt_out!r}"
                )
                continue

            present = variable in values
            circular, ids, bodies, digest = pool_shape(values.get(variable, ""))
            if circular and ids >= MIN_POOL_DEPTH and bodies >= MIN_POOL_DEPTH:
                if raw_opt_out == "1":
                    fail(
                        f"{label}: {opt_out}=1 противоречит рабочему пулу "
                        f"{variable} ({ids} id, {bodies} разных тел)"
                    )
                continue
            if raw_opt_out == "1":
                continue

            key = issue_key(
                "shallow-pool",
                label,
                proto,
                f"present={int(present)}",
                f"sha256={digest}",
                f"circular={int(circular)}",
                f"ids={ids}",
                f"bodies={bodies}",
            )
            if is_waived(key, known, used_known):
                continue
            fail(
                f"{label}: пул {proto} имеет circular={int(circular)}, "
                f"ids={ids}, distinct_bodies={bodies}; нужно минимум "
                f"{MIN_POOL_DEPTH} реальных варианта либо {opt_out}=1; "
                f"waiver key: {key}"
            )

        # 8a. Each exact dialogue fragment is separate debt. A waiver for one
        # phrase cannot hide another phrase added later to the same profile.
        lowered = text.lower()
        for marker in DIALOGUE_MARKERS:
            matching_lines = [
                line.strip()
                for line in lowered.splitlines()
                if marker in line
            ]
            if not matching_lines:
                continue
            occurrence_digest = hashlib.sha256(
                "\n".join(matching_lines).encode("utf-8")
            ).hexdigest()
            key = issue_key(
                "dialogue",
                label,
                marker,
                f"count={len(matching_lines)}",
                f"sha256={occurrence_digest}",
            )
            if is_waived(key, known, used_known):
                continue
            fail(
                f"{label}: в конфиге остался диалоговый фрагмент {marker!r}; "
                f"waiver key: {key}"
            )

        # 8b. The wrong token is part of the waiver identity, so another typo
        # in an already known directory is still rejected.
        lowered_label = label.lower()
        for wrong, right in sorted(NAME_TYPOS.items()):
            if wrong not in lowered_label:
                continue
            key = issue_key("typo", label, wrong, right)
            if is_waived(key, known, used_known):
                continue
            fail(
                f"{label}: опечатка {wrong!r}, ожидается {right!r}; "
                f"waiver key: {key}"
            )

        for name in FORBIDDEN_NEW_IN:
            value = values.get(name)
            if not value:
                continue
            try:
                tokens = shlex.split(value, comments=False, posix=True)
            except ValueError:
                tokens = [value]
            if any(token == "--new" or token.startswith("--new=") for token in tokens):
                fail(f"{label}: `--new` или `--new=имя` внутри {name}")

        custom = values.get("NFQWS_ARGS_CUSTOM", "")
        if custom:
            try:
                custom_tokens = shlex.split(custom, comments=False, posix=True)
            except ValueError:
                custom_tokens = []
                fail(f"{label}: NFQWS_ARGS_CUSTOM не разбирается как shell argv")
            boundaries = [
                index
                for index, token in enumerate(custom_tokens)
                if token == "--new" or token.startswith("--new=")
            ]
            if boundaries and (
                boundaries[0] == 0
                or boundaries[-1] == len(custom_tokens) - 1
                or any(
                    right == left + 1
                    for left, right in zip(boundaries, boundaries[1:])
                )
            ):
                fail(
                    f"{label}: --new в NFQWS_ARGS_CUSTOM должен разделять "
                    "два непустых профиля"
                )
            if "--new=" in custom_tokens:
                fail(f"{label}: пустое имя в --new= внутри NFQWS_ARGS_CUSTOM")

        for blob_name in sorted(set(re.findall(r"[A-Za-z0-9_.-]+\.bin", text))):
            if blob_name in shipped_names or blob_name in declared_external:
                continue
            fail(
                f"{label}: блоб {blob_name} не поставляется нами и не объявлен "
                f"в {REQUIRED_BLOBS.name}"
            )

        tcp_allowed = expand_ports(values.get("TCP_PORTS", ""), ":-")
        udp_allowed = expand_ports(values.get("UDP_PORTS", ""), ":-")
        for arg_name in PORT_FILTER_VARS:
            value = values.get(arg_name)
            if not value:
                continue
            for proto, allowed in (("tcp", tcp_allowed), ("udp", udp_allowed)):
                for spec in re.findall(rf"--filter-{proto}=([0-9,:\-]+)", value):
                    used = expand_ports(spec, "-:")
                    missing = sorted(used - allowed)
                    if missing:
                        preview = ", ".join(str(p) for p in missing[:6])
                        more = "" if len(missing) <= 6 else f" (+{len(missing) - 6})"
                        fail(
                            f"{label}: --filter-{proto} в {arg_name} использует "
                            f"порты вне {proto.upper()}_PORTS: {preview}{more}"
                        )

    # 6. This is deliberately cross-profile: profile switching is where an
    # unnoticed IPv6 policy change becomes a runtime regression.
    check_ipv6_policy(profiles, known, used_known)

    stale = sorted(known - used_known)
    for key in stale:
        fail(
            f"неизвестная или устаревшая waiver-строка {key!r}; "
            "удалите её либо обновите под точную текущую форму долга"
        )

    print(f"blobs: {len(shipped)}, strategies: {len(strategies)}, known issues: {len(known)}")
    if problems:
        print()
        for problem in problems:
            print(f"  FAIL {problem}")
        print()
        print(
            "Если расхождение осознанно и ждёт решения об источнике/лицензии,\n"
            "внесите его в build_scripts/nfqws-assets.known-issues с причиной."
        )
        return 1

    print("nfqws assets gate: OK")
    return 0


def cli(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Verify shipped nfqws2 assets and preset invariants."
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=DEFAULT_REPO_ROOT,
        help=argparse.SUPPRESS,
    )
    args = parser.parse_args(argv)
    configure_repo_root(args.repo_root)
    return main()


if __name__ == "__main__":
    sys.exit(cli(sys.argv[1:]))

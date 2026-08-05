#!/usr/bin/env python3
"""Roadmap: "P0. Ввести единый invariant gate для пресетов и бинарных assets
nfqws2."

Проверяет пять инвариантов из пункта:

  1. уникальность содержимого поставляемых блобов (SHA-256);
  2. SHA-256 manifest — есть и совпадает;
  3. каждая внешняя зависимость объявлена в `required-blobs`;
  4. запрет `--new` внутри NFQWS_BASE_ARGS, NFQWS_ARGS, NFQWS_ARGS_QUIC,
     NFQWS_ARGS_UDP и NFQWS_ARGS_IPSET;
  5. покрытие портов фильтров списками TCP_PORTS / UDP_PORTS.

Чего гейт намеренно НЕ делает: не переименовывает и не удаляет блобы. Правдивость
имени и происхождение — вопрос источника и лицензии, его решает владелец, а не
скрипт. Подтверждённые расхождения живут в `nfqws-assets.known-issues`: сборка
из-за них не падает, но новое расхождение падает, и список не может тихо расти.
"""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SHARE = (
    REPO_ROOT
    / "packages/keenetic/keen-pbr/files/opt/usr/share/keen-pbr"
)
BLOBS = SHARE / "nfqws-blobs"
STRATEGIES = SHARE / "nfqws-strategies"
MANIFEST = BLOBS / "SHA256SUMS"
REQUIRED_BLOBS = SHARE / "nfqws-required-blobs"
KNOWN_ISSUES = REPO_ROOT / "build_scripts" / "nfqws-assets.known-issues"

FORBIDDEN_NEW_IN = (
    "NFQWS_BASE_ARGS",
    "NFQWS_ARGS",
    "NFQWS_ARGS_QUIC",
    "NFQWS_ARGS_UDP",
    "NFQWS_ARGS_IPSET",
)

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


def main() -> int:
    known = load_known_issues()

    if not BLOBS.is_dir() or not STRATEGIES.is_dir():
        print(f"ERROR: asset directories not found under {SHARE}")
        return 2

    shipped = sorted(p for p in BLOBS.iterdir() if p.suffix == ".bin")
    if not shipped:
        print("ERROR: no shipped blobs found; the gate is looking in the wrong place.")
        return 2

    digests: dict[str, list[str]] = {}
    for blob in shipped:
        digest = hashlib.sha256(blob.read_bytes()).hexdigest()
        digests.setdefault(digest, []).append(blob.name)

    # 1. Уникальность содержимого.
    for digest, names in sorted(digests.items()):
        if len(names) > 1:
            key = "duplicate " + " ".join(sorted(names))
            if key not in known:
                fail(
                    f"дубль содержимого: {', '.join(sorted(names))} "
                    f"(sha256 {digest[:16]}…)"
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

    for conf in strategies:
        label = conf.parent.name
        text = conf.read_text(encoding="utf-8")
        values = parse_shell_assignments(text)

        for name in FORBIDDEN_NEW_IN:
            value = values.get(name)
            if value and re.search(r"(^|\s)--new(\s|$)", value):
                fail(f"{label}: `--new` внутри {name}")

        for blob_name in sorted(set(re.findall(r"[A-Za-z0-9_.-]+\.bin", text))):
            if blob_name in shipped_names or blob_name in declared_external:
                continue
            fail(
                f"{label}: блоб {blob_name} не поставляется нами и не объявлен "
                f"в {REQUIRED_BLOBS.name}"
            )

        tcp_allowed = expand_ports(values.get("TCP_PORTS", ""), ":-")
        udp_allowed = expand_ports(values.get("UDP_PORTS", ""), ":-")
        for arg_name in FORBIDDEN_NEW_IN:
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


if __name__ == "__main__":
    sys.exit(main())

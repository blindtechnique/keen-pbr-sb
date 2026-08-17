#!/usr/bin/env python3
"""Roadmap: "P0. Довести OpenAPI до всех зарегистрированных API-путей и добавить
parity gate."

`make generate-check` доказывает только, что уже описанная половина схемы
совпадает с генерируемыми типами. Он по построению не может заметить путь,
которого в схеме нет вовсе. Этот гейт закрывает вторую половину: он находит
фактически зарегистрированные маршруты в `src/api` и сверяет их со схемой.

Регистрация в проекте выглядит двумя способами:

    server.get("/api/...")            server.post("/api/...")
    server.get_stream("/api/...")     impl_->server.Get("/api/auth/...")

Второй способ живёт только в `src/api/server.cpp` (эндпоинты аутентификации
регистрируются напрямую на httplib, минуя обёртку `ApiServer`), и пропустить
его нельзя: это как раз state-changing вход, с которого roadmap велит начинать.

Известные пробелы держим в `build_scripts/openapi-parity.known-gaps`, а не в
молчаливом пропуске. Файл — это долг с именем: новый неописанный путь роняет
гейт, старый виден списком и уменьшается по мере описания.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
API_DIR = REPO_ROOT / "src" / "api"
SPEC = REPO_ROOT / "docs" / "openapi.yaml"
KNOWN_GAPS = REPO_ROOT / "build_scripts" / "openapi-parity.known-gaps"

# `server.get(...)`, `server.post(...)`, `server.get_stream(...)` — обёртка.
WRAPPER = re.compile(
    r"\bserver\.(get|post|put|del|patch)(?:_stream)?\s*\(\s*\"(/api/[^\"]*)\""
)
# `impl_->server.Get("/api/...")` — прямая регистрация на httplib.
DIRECT = re.compile(
    r"\bserver\.(Get|Post|Put|Delete|Patch)\s*\(\s*\"(/api/[^\"]*)\""
)
# Строка пути верхнего уровня в openapi.yaml: ровно два пробела отступа.
SPEC_PATH = re.compile(r"^  (/[A-Za-z0-9_/{}.-]*):\s*$")
SPEC_METHOD = re.compile(r"^    (get|post|put|delete|patch):\s*$")


def normalize(path: str) -> str:
    """Параметр пути приводим к позиции, а не к имени.

    В коде это `/api/lists/` + имя, в схеме — `/api/lists/{name}`. Сравнивать
    имена параметров бессмысленно: они принадлежат разным языкам.
    """
    path = re.sub(r"\{[^}]*\}", "{}", path)
    return path.rstrip("/") or "/"


def collect_registered() -> dict[tuple[str, str], set[str]]:
    found: dict[tuple[str, str], set[str]] = {}
    for source in sorted(API_DIR.rglob("*.cpp")):
        text = source.read_text(encoding="utf-8", errors="replace")
        for pattern in (WRAPPER, DIRECT):
            for method, path in pattern.findall(text):
                key = (normalize(path), method.lower().replace("del", "delete"))
                found.setdefault(key, set()).add(
                    str(source.relative_to(REPO_ROOT))
                )
    return found


def collect_documented() -> set[tuple[str, str]]:
    documented: set[tuple[str, str]] = set()
    current: str | None = None
    in_paths = False
    for line in SPEC.read_text(encoding="utf-8").splitlines():
        if line.startswith("paths:"):
            in_paths = True
            continue
        if in_paths and line and not line[0].isspace():
            in_paths = False
        if not in_paths:
            continue
        match = SPEC_PATH.match(line)
        if match:
            current = normalize(match.group(1))
            continue
        method = SPEC_METHOD.match(line)
        if method and current:
            documented.add((current, method.group(1)))
    return documented


def load_known_gaps() -> set[tuple[str, str]]:
    if not KNOWN_GAPS.exists():
        return set()
    gaps: set[tuple[str, str]] = set()
    for raw in KNOWN_GAPS.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        method, _, path = line.partition(" ")
        gaps.add((normalize(path.strip()), method.strip().lower()))
    return gaps


def main() -> int:
    registered = collect_registered()
    documented = collect_documented()
    known = load_known_gaps()

    if not registered:
        print("ERROR: no routes found in src/api; the extractor is stale.")
        return 2
    if not documented:
        print("ERROR: no paths found in docs/openapi.yaml; the parser is stale.")
        return 2

    missing = sorted(key for key in registered if key not in documented)
    new_missing = [key for key in missing if key not in known]
    fixed = sorted(known - {key for key in missing})

    print(f"registered routes: {len(registered)}")
    print(f"documented operations: {len(documented)}")
    print(f"undocumented: {len(missing)} (known {len(known)})")

    if fixed:
        print()
        print("Эти пути уже описаны — уберите их из known-gaps:")
        for path, method in fixed:
            print(f"  {method.upper()} {path}")

    if new_missing:
        print()
        print("Новые зарегистрированные пути без описания в OpenAPI:")
        for path, method in new_missing:
            where = ", ".join(sorted(registered[(path, method)]))
            print(f"  {method.upper()} {path}  ({where})")
        print()
        print(
            "Опишите путь в docs/openapi.yaml и запустите `make generate`,\n"
            "либо, если описание откладывается осознанно, внесите путь в\n"
            "build_scripts/openapi-parity.known-gaps с причиной."
        )
        return 1

    if fixed:
        return 1

    print("openapi parity gate: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())

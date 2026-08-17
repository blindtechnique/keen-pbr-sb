#!/usr/bin/env bash
# Roadmap: "P1. Подключить уже настроенный `clang-tidy` без замедления каждого
# alpha build. … сначала запускать curated checks на изменённых файлах либо
# отдельным nightly job, а полный скан сделать блокирующим лишь после
# устранения подтверждённых дефектов и стабилизации времени."
#
# Отличие от `make clang-tidy`: тот гоняет clangd-tidy по всему дереву и требует
# clangd. Здесь — обычный clang-tidy по curated-набору каталогов, тех, где
# ошибка дороже всего. На двух ядрах это около часа против нескольких часов
# полного скана.
#
# Гейтом сборки не является: печатает находки и всегда завершается успешно.
# Блокирующим его можно делать только после разбора базовой линии, как и
# написано в пункте.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build_dir="${1:-$repo_root/build/cmake-clang-tidy}"
jobs="${CLANG_TIDY_JOBS:-2}"

tidy_bin="${CLANG_TIDY:-}"
if [ -z "$tidy_bin" ]; then
  for candidate in clang-tidy-20 clang-tidy-19 clang-tidy-18 clang-tidy; do
    if command -v "$candidate" >/dev/null 2>&1; then
      tidy_bin="$candidate"
      break
    fi
  done
fi
if [ -z "$tidy_bin" ]; then
  echo "ERROR: clang-tidy not found. Install clang-tidy or set CLANG_TIDY=..." >&2
  exit 2
fi

if [ ! -f "$build_dir/compile_commands.json" ]; then
  echo "ERROR: no compile_commands.json in $build_dir." >&2
  echo "Configure a Clang build with -DCMAKE_EXPORT_COMPILE_COMMANDS=ON first." >&2
  exit 2
fi

# Каталоги, где падение или молчаливый отказ стоят дороже всего: работа с
# ядром, файрволом, восстановлением и разбором внешних данных.
curated_dirs=(
  /src/runtime/
  /src/firewall/
  /src/routing/
  /src/lists/
  /src/dns/
  /src/backup/
  /src/connections/
  /src/config/
)

files="$(python3 - "$build_dir/compile_commands.json" "${curated_dirs[@]}" <<'PY'
import json, sys
db = json.load(open(sys.argv[1]))
wanted = sys.argv[2:]
seen = sorted({
    entry["file"]
    for entry in db
    if entry["file"].endswith(".cpp")
    and any(part in entry["file"] for part in wanted)
})
print("\n".join(seen))
PY
)"

count="$(printf '%s\n' "$files" | grep -c . || true)"
if [ "$count" -eq 0 ]; then
  echo "ERROR: curated selection is empty; the directory list is stale." >&2
  exit 2
fi

echo "clang-tidy ($tidy_bin): $count translation units, $jobs jobs"
printf '%s\n' "$files" \
  | xargs -P "$jobs" -I FILE "$tidy_bin" -p "$build_dir" --quiet FILE \
  || true

echo
echo "Базовая линия и разбор находок: build_scripts/clang-tidy-baseline.md"

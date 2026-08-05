#!/usr/bin/env bash
# Roadmap: "P0. Проверять каждый поставляемый shell-скрипт целевым BusyBox."
#
# Проверка не заменяет запуск на роутере — она блокирует публикацию заведомо
# непарсящегося пакета и ловит bashisms до сборки IPK.
#
# Два прохода:
#   1) `busybox sh -n` — разбор целевым ash, а не хостовым bash;
#   2) поиск конструкций, которые ash разбирает, но выполняет иначе либо не
#      поддерживает (`[[`, `local -`, `echo -e`, `<<<`, массивы, `source`).
#
# Второй проход нарочно точечный. Наивный шаблон `\[\[` ловит POSIX-класс
# `[[:space:]]`, которого в этих скриптах много, и гейт мгновенно превращается
# в шум, который начинают отключать.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

busybox_bin="${BUSYBOX:-busybox}"
if ! command -v "$busybox_bin" >/dev/null 2>&1; then
  echo "ERROR: busybox not found. Install busybox-static or set BUSYBOX=/path/to/busybox." >&2
  exit 2
fi

# Скрипты, которые попадают в пакет либо запускаются на устройстве. Debian и
# OpenWrt здесь тоже: их постинсталляционные скрипты выполняются dash/ash, и
# bashism в них ломает установку так же тихо.
roots=(
  packages/keenetic
  packages/debian/files
  packages/debian/full/debian
  packages/debian/headless/debian
  packages/openwrt
  install.sh
  uninstall.sh
)

is_shell_script() {
  local file="$1"
  case "$file" in
    *.sh) return 0 ;;
  esac
  # Скрипты без расширения опознаём по shebang, а не по имени: init-скрипты и
  # NDM-hook называются как угодно.
  head -c 128 "$file" 2>/dev/null | head -n 1 | grep -qE '^#!.*(^|/)(ash|dash|sh)([[:space:]]|$)'
}

mapfile -t candidates < <(
  for root in "${roots[@]}"; do
    [ -e "$root" ] || continue
    if [ -f "$root" ]; then
      echo "$root"
    else
      find "$root" -type f
    fi
  done | sort -u
)

scripts=()
for file in "${candidates[@]}"; do
  if is_shell_script "$file"; then
    scripts+=("$file")
  fi
done

if [ "${#scripts[@]}" -eq 0 ]; then
  echo "ERROR: no shipped shell scripts found; the roots list is stale." >&2
  exit 2
fi

failures=0

echo "== busybox sh -n (${#scripts[@]} scripts) =="
for file in "${scripts[@]}"; do
  if ! "$busybox_bin" sh -n "$file" 2>/tmp/busybox-check-$$.err; then
    echo "FAIL parse: $file"
    sed 's/^/    /' /tmp/busybox-check-$$.err
    failures=$((failures + 1))
  fi
done
rm -f /tmp/busybox-check-$$.err

# Каждый шаблон описан причиной: гейт, про который нельзя объяснить "почему",
# рано или поздно обходят вместо того, чтобы чинить.
#
# Шаблон и причина лежат в двух параллельных массивах, а не в одной строке через
# разделитель: почти в каждом шаблоне есть POSIX-класс `[[:space:]]`, и любой
# разделитель-символ внутри него режет шаблон пополам. Первая версия этого файла
# ровно так и молчала на заведомо плохом скрипте.
bashism_patterns=(
  '(\[\[[[:space:]])|(\[\[$)'
  '(^|[^[:alnum:]_])function[[:space:]]+[A-Za-z_]'
  '<<<'
  '(^|[[:space:]])declare[[:space:]]'
  '(^|[[:space:]])local[[:space:]]+-'
  '(^|[[:space:]])echo[[:space:]]+-e([[:space:]]|$)'
  '(^|[[:space:]])source[[:space:]]'
  '(^|[[:space:]])(pushd|popd)([[:space:]]|$)'
  '&>[^>]'
  '\$\{[A-Za-z_][A-Za-z0-9_]*\['
  '\$\{[A-Za-z_][A-Za-z0-9_]*\^'
)
bashism_reasons=(
  '[[ ... ]] is a bash keyword; ash has only [ ... ]'
  'the `function name` form is bash-only; use `name()`'
  'here-strings are bash-only'
  '`declare` is bash-only; use plain assignment or `local`'
  '`local -x` flags are bash-only'
  '`echo -e` is not portable; use printf'
  '`source` is bash-only; use `.`'
  'dirstack builtins are bash-only'
  '`&>` redirection is bash-only; use `>file 2>&1`'
  'array subscripts are bash-only'
  'case-conversion expansion is bash-only'
)

echo
echo "== bashisms =="
for index in "${!bashism_patterns[@]}"; do
  pattern="${bashism_patterns[$index]}"
  reason="${bashism_reasons[$index]}"
  if hits="$(grep -nE "$pattern" "${scripts[@]}" 2>/dev/null)"; then
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      echo "FAIL bashism: $line"
      echo "    reason: $reason"
      failures=$((failures + 1))
    done <<EOF
$hits
EOF
  fi
done

echo
if [ "$failures" -ne 0 ]; then
  echo "busybox shell gate: $failures problem(s) in ${#scripts[@]} scripts"
  exit 1
fi
echo "busybox shell gate: ${#scripts[@]} scripts OK ($("$busybox_bin" 2>&1 | head -n 1 | cut -d' ' -f1-2))"

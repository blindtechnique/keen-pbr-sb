#!/bin/sh
# Докладывает libcronet.so — сетевой стек Chromium, без которого sing-box не
# умеет naive.
#
# Библиотека лежит в том же архиве, что и сам sing-box, но весит десятки
# мегабайт, поэтому установщик её не разворачивает: на роутере с маленькой
# флешкой платить за протокол, которым пользуются единицы, неправильно.
# Скрипт вызывается только тогда, когда naive-транспорт действительно нужен.
#
# Кладём в /opt/lib: туда уже смотрит обёртка, которой мы запускаем sing-box
# на Entware (--library-path /opt/lib:/opt/usr/lib).

set -eu

TARGET_DIR="${KEEN_PBR_NAIVE_LIB_DIR:-/opt/lib}"
TARGET="$TARGET_DIR/libcronet.so"
GITHUB_API="${KEEN_PBR_GITHUB_API:-https://api.github.com}"

log() { echo "$*"; }
die() { echo "$*" >&2; exit 1; }

if [ -f "$TARGET" ]; then
    log "Компонент уже установлен: $TARGET"
    exit 0
fi

command -v tar >/dev/null 2>&1 || die "в системе нет tar"
command -v curl >/dev/null 2>&1 || die "в системе нет curl"

# Версия берётся у самого sing-box: библиотека и бинарник должны быть из
# одного выпуска, иначе символы не сойдутся.
version="$(/opt/bin/sing-box version 2>/dev/null | awk '/^sing-box version/ { print $3; exit }')"
[ -n "$version" ] || die "не удалось определить версию установленного sing-box"

case "$(uname -m)" in
    aarch64|arm64) arch="arm64" ;;
    x86_64|amd64)  arch="amd64" ;;
    *) die "для архитектуры $(uname -m) официальной сборки с naive нет" ;;
esac

asset="sing-box-${version}-linux-${arch}.tar.gz"
url="https://github.com/SagerNet/sing-box/releases/download/v${version}/${asset}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

log "Скачиваю $asset"
curl -fsSL --connect-timeout 15 -o "$tmp/$asset" "$url" || die "не удалось скачать архив sing-box"

# GitHub publishes a SHA-256 digest for every release asset in its API.  Fail
# closed: unpacking an unverified native library as root is worse than leaving
# the optional Naive component unavailable.
metadata="$tmp/release.json"
curl -fsSL --connect-timeout 15 \
    -H "Accept: application/vnd.github+json" \
    -H "User-Agent: keen-pbr-sb" \
    -o "$metadata" \
    "$GITHUB_API/repos/SagerNet/sing-box/releases/tags/v${version}" \
    || die "не удалось получить контрольную сумму релиза sing-box"
expected="$(awk -v wanted="$asset" '
    index($0, "\"name\": \"" wanted "\"") { found = 1 }
    found && /"digest": "sha256:/ {
        sub(/^.*"digest": "sha256:/, "")
        sub(/".*$/, "")
        print
        exit
    }
' "$metadata")"
case "$expected" in
    [0-9a-fA-F][0-9a-fA-F]*) ;;
    *) die "GitHub не вернул SHA-256 для $asset" ;;
esac
[ "${#expected}" -eq 64 ] || die "GitHub вернул некорректный SHA-256 для $asset"

if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$tmp/$asset" | awk '{print $1}')"
elif command -v openssl >/dev/null 2>&1; then
    actual="$(openssl dgst -sha256 "$tmp/$asset" | awk '{print $NF}')"
else
    die "для проверки архива нужен sha256sum или openssl"
fi
[ "$(printf '%s' "$actual" | tr 'A-F' 'a-f')" = "$(printf '%s' "$expected" | tr 'A-F' 'a-f')" ] \
    || die "SHA-256 архива sing-box не совпадает; установка остановлена"
log "SHA-256 архива проверен"

log "Распаковываю libcronet.so"
tar -xzf "$tmp/$asset" -C "$tmp" || die "архив sing-box не распаковывается"

library="$(find "$tmp" -type f -name libcronet.so | head -n 1)"
[ -n "$library" ] || die "в архиве sing-box ${version} нет libcronet.so: в этой сборке naive не поддерживается"

mkdir -p "$TARGET_DIR"
# Через временный файл: оборванная запись оставила бы обрубок, который
# sing-box примет за настоящую библиотеку и упадёт уже при запуске.
cp "$library" "$TARGET.tmp"
chmod 0644 "$TARGET.tmp"
mv "$TARGET.tmp" "$TARGET"

log "Готово: $TARGET ($(wc -c < "$TARGET") байт)"

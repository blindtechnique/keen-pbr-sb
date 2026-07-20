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

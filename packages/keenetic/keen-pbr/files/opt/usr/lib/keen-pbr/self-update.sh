#!/bin/sh

set -eu

RUN_FILE=/opt/var/run/keen-pbr-self-update.pid
LOG_FILE=/opt/var/log/keen-pbr-self-update.log
INSTALLER=/tmp/keen-pbr-sb-update-installer.sh
RELEASE_JSON=/tmp/keen-pbr-sb-update-release.json
RELEASE_API=https://api.github.com/repos/blindtechnique/keen-pbr-sb/releases/latest

mkdir -p /opt/var/run /opt/var/log
printf '%s\n' "$$" > "$RUN_FILE"
cleanup() {
    rm -f "$RUN_FILE" "$INSTALLER" "$RELEASE_JSON"
}
trap cleanup EXIT INT TERM

exec >>"$LOG_FILE" 2>&1
printf '\n[%s] Проверка обновления keen-pbr-sb\n' "$(date '+%Y-%m-%d %H:%M:%S')"

fetch_url() {
    output=$1
    url=$2
    if [ -x /opt/bin/curl ]; then
        /opt/bin/curl -fL --connect-timeout 15 --retry 3 -o "$output" "$url"
    elif command -v curl >/dev/null 2>&1; then
        curl -fL --connect-timeout 15 --retry 3 -o "$output" "$url"
    elif [ -x /opt/bin/wget ]; then
        /opt/bin/wget -O "$output" "$url"
    else
        echo "ОШИБКА: для обновления требуется curl или wget с поддержкой HTTPS"
        exit 1
    fi
}

fetch_url "$RELEASE_JSON" "$RELEASE_API"
release_tag=$(grep '"tag_name"' "$RELEASE_JSON" | head -n 1 | cut -d '"' -f 4)
case "$release_tag" in
    ""|*[!A-Za-z0-9._-]*) echo "ОШИБКА: GitHub вернул некорректный тег выпуска"; exit 1 ;;
esac
INSTALLER_URL="https://raw.githubusercontent.com/blindtechnique/keen-pbr-sb/$release_tag/install.sh"
fetch_url "$INSTALLER" "$INSTALLER_URL"

/bin/sh "$INSTALLER" --update
printf '[%s] Обновление завершено успешно\n' "$(date '+%Y-%m-%d %H:%M:%S')"

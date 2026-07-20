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
# The GitHub API may answer with pretty-printed or compact JSON. Splitting on
# commas first makes the extraction work for both instead of relying on the
# tag sitting alone on its own line.
release_tag=$(tr ',' '\n' < "$RELEASE_JSON" \
    | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
    | head -n 1)
case "$release_tag" in
    ""|*[!A-Za-z0-9._-]*) echo "ОШИБКА: GitHub вернул некорректный тег выпуска"; exit 1 ;;
esac
INSTALLER_URL="https://raw.githubusercontent.com/blindtechnique/keen-pbr-sb/$release_tag/install.sh"
fetch_url "$INSTALLER" "$INSTALLER_URL"

/bin/sh "$INSTALLER" --update

# opkg restarts keen-pbr through the package scripts, but dnsmasq only picks up
# our conf-script on a real restart. Doing it explicitly here - and checking the
# result - keeps an update from leaving the resolver on the previous config,
# which silently disables domain-based routing until the router is rebooted.
printf '[%s] Переподключаю конфигурацию dnsmasq\n' "$(date '+%Y-%m-%d %H:%M:%S')"
if /opt/usr/lib/keen-pbr/dnsmasq.sh activate; then
    printf '[%s] dnsmasq перечитал конфигурацию\n' "$(date '+%Y-%m-%d %H:%M:%S')"
else
    printf '[%s] ПРЕДУПРЕЖДЕНИЕ: dnsmasq не удалось перезапустить. Доменная маршрутизация будет работать только после перезагрузки роутера.\n' \
        "$(date '+%Y-%m-%d %H:%M:%S')"
fi

printf '[%s] Обновление завершено успешно\n' "$(date '+%Y-%m-%d %H:%M:%S')"

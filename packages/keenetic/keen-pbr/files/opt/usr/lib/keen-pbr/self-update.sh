#!/bin/sh

set -eu

RUN_FILE=/opt/var/run/keen-pbr-self-update.pid
LOG_FILE=/opt/var/log/keen-pbr-self-update.log
STATE_FILE=/opt/var/run/keen-pbr-self-update.json
INSTALLER=/tmp/keen-pbr-sb-update-installer.sh
RELEASE_JSON=/tmp/keen-pbr-sb-update-release.json
RELEASE_API=https://api.github.com/repos/blindtechnique/keen-pbr-sb/releases/latest

mkdir -p /opt/var/run /opt/var/log
printf '%s\n' "$$" > "$RUN_FILE"

write_state() {
    phase=$1
    percent=$2
    message=$3
    success=$4
    running=$5
    state_tmp="${STATE_FILE}.tmp.$$"
    if ! printf '{"phase":"%s","percent":%s,"message":"%s","success":%s,"running":%s,"updated_at":%s}\n' \
        "$phase" "$percent" "$message" "$success" "$running" "$(date +%s)" > "$state_tmp"; then
        rm -f "$state_tmp"
        return 0
    fi
    mv -f "$state_tmp" "$STATE_FILE" || rm -f "$state_tmp"
}

finished=0
cleanup() {
    status=$?
    if [ "$status" -ne 0 ] && [ "$finished" -eq 0 ]; then
        write_state failed 100 "Обновление завершилось с ошибкой" false false
    fi
    rm -f "$RUN_FILE" "$INSTALLER" "$RELEASE_JSON"
    trap - EXIT INT TERM
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

: > "$LOG_FILE"
exec >>"$LOG_FILE" 2>&1
write_state checking 5 "Проверяю опубликованную версию" null true
printf '[%s] Проверка обновления keen-pbr-sb\n' "$(date '+%Y-%m-%d %H:%M:%S')"

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
write_state release 15 "Проверяю выпуск GitHub" null true
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
write_state installer 30 "Установщик загружен" null true

write_state installing 40 "Устанавливаю пакет keen-pbr-sb" null true
/bin/sh "$INSTALLER" --update
write_state installed 90 "Пакет установлен, службы перезапущены" null true

# postinst starts keen-pbr through S80keen-pbr. That init script activates the
# managed resolver entry and performs the required dnsmasq restart. Repeating
# the activation here caused a second DNS interruption and opened a race with
# the freshly started daemon.

printf '[%s] Обновление завершено успешно\n' "$(date '+%Y-%m-%d %H:%M:%S')"
finished=1
write_state completed 100 "Обновление завершено успешно" true false

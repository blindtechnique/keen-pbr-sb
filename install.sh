#!/bin/sh

set -eu
umask 077

PROJECT_REPOSITORY="${MYKEENPBR_REPOSITORY:-blindtechnique/keen-pbr-sb}"
GITHUB_API="https://api.github.com/repos"
SING_BOX_TESTED_VERSION="1.13.14"
TMP_DIR=
TRANSPORT_CONFIG="/opt/etc/keen-pbr/transports.json"
RESCUE_DIR="/opt/var/lib/keen-pbr/rescue"
RESCUE_HELPER="$RESCUE_DIR/rescue-update.sh"
LOCK_HELPER="$RESCUE_DIR/update-lock.sh"
LOCK_DIR="/opt/var/run/keen-pbr-update.lock"
UPDATE_ONLY=0
LOCK_OWNER_PID=${KEEN_PBR_UPDATE_LOCK_PID:-}
LOCK_TOKEN=${KEEN_PBR_UPDATE_LOCK_TOKEN:-}
LOCK_OWNED=0
LOCK_RETURN_PID=
LOCK_HELPER_V2=0
FALLBACK_CLEANUP_OWNED=0

case "${1:-}" in
    --update) UPDATE_ONLY=1 ;;
    "") ;;
    *) printf '%s\n' "ОШИБКА: неизвестный параметр: $1" >&2; exit 2 ;;
esac

cleanup() {
    status=$?
    case "$TMP_DIR" in
        /*/mykeenpbr-install.*) rm -rf "$TMP_DIR" ;;
    esac
    if [ "$FALLBACK_CLEANUP_OWNED" -eq 1 ]; then
        rm -f "${LOCK_DIR}.cleanup/ready" "${LOCK_DIR}.cleanup/pid" \
            "${LOCK_DIR}.cleanup/start" 2>/dev/null || true
        rmdir "${LOCK_DIR}.cleanup" 2>/dev/null || true
        FALLBACK_CLEANUP_OWNED=0
    fi
    if [ "$LOCK_OWNED" -eq 1 ]; then
        if [ -x "$LOCK_HELPER" ] &&
           [ "$("$LOCK_HELPER" version 2>/dev/null || true)" = "2" ]; then
            if [ -n "$LOCK_RETURN_PID" ] &&
               "$LOCK_HELPER" transfer "$LOCK_OWNER_PID" "$LOCK_TOKEN" \
                   "$LOCK_RETURN_PID" >/dev/null 2>&1; then
                LOCK_OWNED=0
            else
                "$LOCK_HELPER" release "$LOCK_OWNER_PID" "$LOCK_TOKEN" \
                    >/dev/null 2>&1 || true
            fi
        elif [ -d "$LOCK_DIR" ] && [ ! -L "$LOCK_DIR" ]; then
            owner_pid=""
            owner_token=""
            IFS= read -r owner_pid < "$LOCK_DIR/pid" 2>/dev/null || true
            IFS= read -r owner_token < "$LOCK_DIR/token" 2>/dev/null || true
            if [ "$owner_pid" = "$LOCK_OWNER_PID" ] &&
               [ "$owner_token" = "$LOCK_TOKEN" ]; then
                rm -f "$LOCK_DIR/ready" "$LOCK_DIR/owner" \
                    "$LOCK_DIR/token" "$LOCK_DIR/pid" "$LOCK_DIR/start"
                rmdir "$LOCK_DIR" 2>/dev/null || true
            fi
        fi
    fi
    trap - EXIT INT TERM
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

valid_lock_pid() {
    case "${1:-}" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ "$1" -gt 1 ] 2>/dev/null
}

lock_process_start_time() {
    valid_lock_pid "${1:-}" || return 1
    [ -r "/proc/$1/stat" ] || return 1
    stat_line=$(cat "/proc/$1/stat") || return 1
    stat_tail=${stat_line##*) }
    set -- $stat_tail
    [ "$#" -ge 20 ] || return 1
    start_time=${20}
    case "$start_time" in
        ''|*[!0-9]*) return 1 ;;
    esac
    printf '%s\n' "$start_time"
}

fallback_owner_is_alive() {
    owner_pid=$1
    owner_start=$2
    valid_lock_pid "$owner_pid" && kill -0 "$owner_pid" 2>/dev/null ||
        return 1
    case "$owner_start" in
        ''|*[!0-9]*) return 1 ;;
    esac
    current_start=$(lock_process_start_time "$owner_pid") || return 1
    [ "$current_start" = "$owner_start" ]
}

fallback_recorded_owner_is_alive() {
    recorded_pid=$1
    recorded_start=$2
    if [ -z "$recorded_start" ]; then
        valid_lock_pid "$recorded_pid" &&
            kill -0 "$recorded_pid" 2>/dev/null
        return $?
    fi
    fallback_owner_is_alive "$recorded_pid" "$recorded_start"
}

fallback_lock_held_by() {
    [ -d "$LOCK_DIR" ] && [ ! -L "$LOCK_DIR" ] &&
        [ -f "$LOCK_DIR/ready" ] && [ -f "$LOCK_DIR/start" ] ||
        return 1
    owner_pid=""
    owner_start=""
    owner_token=""
    IFS= read -r owner_pid < "$LOCK_DIR/pid" || return 1
    IFS= read -r owner_start < "$LOCK_DIR/start" || return 1
    IFS= read -r owner_token < "$LOCK_DIR/token" || return 1
    valid_lock_pid "$owner_pid" &&
        [ "$owner_pid" = "$1" ] && [ "$owner_token" = "$2" ] &&
        fallback_owner_is_alive "$owner_pid" "$owner_start"
}

legacy_lock_held_by() {
    [ -d "$LOCK_DIR" ] && [ ! -L "$LOCK_DIR" ] &&
        [ -f "$LOCK_DIR/ready" ] && [ ! -L "$LOCK_DIR/ready" ] &&
        [ -f "$LOCK_DIR/pid" ] && [ ! -L "$LOCK_DIR/pid" ] &&
        [ -f "$LOCK_DIR/token" ] && [ ! -L "$LOCK_DIR/token" ] ||
        return 1
    legacy_pid=""
    legacy_token=""
    IFS= read -r legacy_pid < "$LOCK_DIR/pid" || return 1
    IFS= read -r legacy_token < "$LOCK_DIR/token" || return 1
    valid_lock_pid "$legacy_pid" &&
        [ "$legacy_pid" = "$1" ] && [ "$legacy_token" = "$2" ] &&
        kill -0 "$legacy_pid" 2>/dev/null
}

adopt_legacy_lock() {
    previous_owner=$1
    token=$2
    legacy_lock_held_by "$previous_owner" "$token" || return 1
    adopted_start=$(lock_process_start_time "$$") || return 1
    pid_tmp="$LOCK_DIR/pid.tmp.$$"
    start_tmp="$LOCK_DIR/start.tmp.$$"
    if ! chmod 0700 "$LOCK_DIR" ||
       ! chmod 0600 "$LOCK_DIR/token" "$LOCK_DIR/ready" ||
       ! printf 'ready\n' > "$LOCK_DIR/ready" ||
       ! printf '%s\n' "$$" > "$pid_tmp" ||
       ! printf '%s\n' "$adopted_start" > "$start_tmp" ||
       ! chmod 0600 "$pid_tmp" "$start_tmp" ||
       ! mv -f "$start_tmp" "$LOCK_DIR/start" ||
       ! mv -f "$pid_tmp" "$LOCK_DIR/pid" ||
       ! chmod 0600 "$LOCK_DIR/ready"; then
        rm -f "$pid_tmp" "$start_tmp"
        return 1
    fi
    [ "$previous_owner" = "$$" ] || LOCK_RETURN_PID=$previous_owner
    LOCK_OWNER_PID=$$
    LOCK_TOKEN=$token
    LOCK_OWNED=1
    export KEEN_PBR_UPDATE_LOCK_PID="$LOCK_OWNER_PID"
    export KEEN_PBR_UPDATE_LOCK_TOKEN="$LOCK_TOKEN"
}

fallback_release_cleanup_guard() {
    [ "$FALLBACK_CLEANUP_OWNED" -eq 1 ] || return 0
    cleanup_lock="${LOCK_DIR}.cleanup"
    rm -f "$cleanup_lock/ready" "$cleanup_lock/pid" \
        "$cleanup_lock/start" 2>/dev/null || true
    rmdir "$cleanup_lock" 2>/dev/null || true
    FALLBACK_CLEANUP_OWNED=0
}

fallback_acquire_cleanup_guard() {
    cleanup_lock="${LOCK_DIR}.cleanup"
    attempts=0
    while [ "$attempts" -lt 2 ]; do
        if mkdir "$cleanup_lock" 2>/dev/null; then
            chmod 0700 "$cleanup_lock" || {
                rmdir "$cleanup_lock" 2>/dev/null || true
                return 1
            }
            cleanup_start=$(lock_process_start_time "$$") || {
                rmdir "$cleanup_lock" 2>/dev/null || true
                return 1
            }
            if ! printf '%s\n' "$$" > "$cleanup_lock/pid" ||
               ! printf '%s\n' "$cleanup_start" > "$cleanup_lock/start" ||
               ! printf 'ready\n' > "$cleanup_lock/ready" ||
               ! chmod 0600 "$cleanup_lock/pid" "$cleanup_lock/start" \
                    "$cleanup_lock/ready"; then
                rm -f "$cleanup_lock/ready" "$cleanup_lock/pid" \
                    "$cleanup_lock/start"
                rmdir "$cleanup_lock" 2>/dev/null || true
                return 1
            fi
            FALLBACK_CLEANUP_OWNED=1
            return 0
        fi

        [ -d "$cleanup_lock" ] && [ ! -L "$cleanup_lock" ] || return 1
        cleanup_pid=""
        cleanup_start=""
        IFS= read -r cleanup_pid < "$cleanup_lock/pid" 2>/dev/null || true
        IFS= read -r cleanup_start < "$cleanup_lock/start" 2>/dev/null || true
        if [ -f "$cleanup_lock/ready" ] &&
           fallback_recorded_owner_is_alive "$cleanup_pid" "$cleanup_start"; then
            return 1
        fi
        sleep 1
        cleanup_pid=""
        cleanup_start=""
        IFS= read -r cleanup_pid < "$cleanup_lock/pid" 2>/dev/null || true
        IFS= read -r cleanup_start < "$cleanup_lock/start" 2>/dev/null || true
        if [ -f "$cleanup_lock/ready" ] &&
           fallback_recorded_owner_is_alive "$cleanup_pid" "$cleanup_start"; then
            return 1
        fi
        rm -f "$cleanup_lock/ready" "$cleanup_lock/pid" \
            "$cleanup_lock/start" 2>/dev/null || true
        rmdir "$cleanup_lock" 2>/dev/null || return 1
        attempts=$((attempts + 1))
    done
    return 1
}

fallback_remove_stale_lock() {
    cleanup_lock="${LOCK_DIR}.cleanup"
    fallback_acquire_cleanup_guard || return 1

    owner_pid=""
    owner_start=""
    IFS= read -r owner_pid < "$LOCK_DIR/pid" 2>/dev/null || true
    IFS= read -r owner_start < "$LOCK_DIR/start" 2>/dev/null || true
    if valid_lock_pid "$owner_pid" &&
       fallback_recorded_owner_is_alive "$owner_pid" "$owner_start"; then
        fallback_release_cleanup_guard
        return 1
    fi
    if [ -L "$LOCK_DIR" ] ||
       { [ -e "$LOCK_DIR" ] && [ ! -d "$LOCK_DIR" ]; }; then
        fallback_release_cleanup_guard
        return 1
    fi

    if [ -d "$LOCK_DIR" ] && [ ! -f "$LOCK_DIR/ready" ]; then
        sleep 1
        owner_pid=""
        owner_start=""
        IFS= read -r owner_pid < "$LOCK_DIR/pid" 2>/dev/null || true
        IFS= read -r owner_start < "$LOCK_DIR/start" 2>/dev/null || true
        if valid_lock_pid "$owner_pid" &&
           fallback_recorded_owner_is_alive "$owner_pid" "$owner_start"; then
            fallback_release_cleanup_guard
            return 1
        fi
    fi
    rm -f "$LOCK_DIR/ready" "$LOCK_DIR/owner" "$LOCK_DIR/token" \
        "$LOCK_DIR/pid" "$LOCK_DIR/start" 2>/dev/null || true
    if ! rmdir "$LOCK_DIR" 2>/dev/null; then
        fallback_release_cleanup_guard
        return 1
    fi
    fallback_release_cleanup_guard
}

fallback_discard_owned_lock() {
    rm -f "$LOCK_DIR/ready" "$LOCK_DIR/owner" "$LOCK_DIR/token" \
        "$LOCK_DIR/pid" "$LOCK_DIR/start" 2>/dev/null || true
    rmdir "$LOCK_DIR" 2>/dev/null || true
}

acquire_update_lock() {
    mkdir -p "$(dirname "$LOCK_DIR")" || return 1
    if [ -x "$LOCK_HELPER" ] &&
       [ "$("$LOCK_HELPER" version 2>/dev/null || true)" = "2" ]; then
        LOCK_HELPER_V2=1
    else
        LOCK_HELPER_V2=0
    fi
    if [ -n "$LOCK_OWNER_PID" ] || [ -n "$LOCK_TOKEN" ]; then
        [ -n "$LOCK_OWNER_PID" ] && [ -n "$LOCK_TOKEN" ] ||
            return 1
        if [ "$LOCK_HELPER_V2" -eq 1 ]; then
            if [ "$LOCK_OWNER_PID" != "$$" ]; then
                LOCK_RETURN_PID=$LOCK_OWNER_PID
                LOCK_TOKEN=$("$LOCK_HELPER" transfer \
                    "$LOCK_OWNER_PID" "$LOCK_TOKEN" "$$") || return $?
                LOCK_OWNER_PID=$$
                LOCK_OWNED=1
                export KEEN_PBR_UPDATE_LOCK_PID="$LOCK_OWNER_PID"
                export KEEN_PBR_UPDATE_LOCK_TOKEN="$LOCK_TOKEN"
                return 0
            fi
            "$LOCK_HELPER" held "$LOCK_OWNER_PID" "$LOCK_TOKEN"
        else
            adopt_legacy_lock "$LOCK_OWNER_PID" "$LOCK_TOKEN"
        fi
        return $?
    fi

    LOCK_OWNER_PID=$$
    if [ "$LOCK_HELPER_V2" -eq 1 ]; then
        LOCK_TOKEN=$("$LOCK_HELPER" acquire "$LOCK_OWNER_PID") || return $?
    else
        if ! mkdir "$LOCK_DIR" 2>/dev/null; then
            fallback_remove_stale_lock || return 75
            mkdir "$LOCK_DIR" 2>/dev/null || return 75
        fi
        chmod 0700 "$LOCK_DIR" || {
            fallback_discard_owned_lock
            return 1
        }
        LOCK_TOKEN="${LOCK_OWNER_PID}.$(date +%s)"
        LOCK_START=$(lock_process_start_time "$LOCK_OWNER_PID") || {
            fallback_discard_owned_lock
            return 1
        }
        if ! printf '%s\n' "$LOCK_OWNER_PID" > "$LOCK_DIR/pid" ||
           ! printf '%s\n' "$LOCK_START" > "$LOCK_DIR/start" ||
           ! printf '%s\n' "$LOCK_TOKEN" > "$LOCK_DIR/token" ||
           ! printf 'ready\n' > "$LOCK_DIR/ready" ||
           ! chmod 0600 "$LOCK_DIR/pid" "$LOCK_DIR/start" \
                "$LOCK_DIR/token" "$LOCK_DIR/ready"; then
            fallback_discard_owned_lock
            return 1
        fi
    fi
    LOCK_OWNED=1
    export KEEN_PBR_UPDATE_LOCK_PID="$LOCK_OWNER_PID"
    export KEEN_PBR_UPDATE_LOCK_TOKEN="$LOCK_TOKEN"
}

say() {
    printf '%s\n' "$*"
}

die() {
    say "ОШИБКА: $*" >&2
    exit 1
}

ask() {
    prompt="$1"
    default="$2"
    printf '%s ' "$prompt" >/dev/tty
    answer=""
    IFS= read -r answer </dev/tty || true
    [ -n "$answer" ] || answer="$default"
    printf '%s' "$answer"
}

ask_secret() {
    prompt="$1"
    printf '%s ' "$prompt" >/dev/tty
    stty -echo </dev/tty 2>/dev/null || true
    answer=""
    IFS= read -r answer </dev/tty || true
    stty echo </dev/tty 2>/dev/null || true
    printf '\n' >/dev/tty
    printf '%s' "$answer"
}

fetch() {
    url="$1"
    output="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fL --connect-timeout 15 --max-time 180 \
            --retry 3 -o "$output" "$url"
    elif [ -x /opt/bin/curl ]; then
        /opt/bin/curl -fL --connect-timeout 15 --max-time 180 \
            --retry 3 -o "$output" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -T 60 -O "$output" "$url"
    else
        die "требуется curl или wget"
    fi
}

github_asset_urls() {
    # Tolerate both pretty-printed and compact GitHub API responses.
    tr ',' '\n' < "$1" \
        | sed -n 's/.*"browser_download_url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'
}

detect_target() {
    [ -x /opt/bin/opkg ] || die "Entware не подключён в /opt"
    architecture=$(/opt/bin/opkg print-architecture | awk '
        $2 != "all" && $2 !~ /_kn$/ && $3 >= priority { arch=$2; priority=$3 }
        END { print arch }
    ')
    case "$architecture" in
        aarch64-*) KEEN_ARCH="aarch64" ;;
        armv7-*) KEEN_ARCH="armv7" ;;
        mipsel-*) KEEN_ARCH="mipsel" ;;
        mips-*) KEEN_ARCH="mips" ;;
        x64-*) KEEN_ARCH="x64" ;;
        *) die "неподдерживаемая архитектура Entware: ${architecture:-неизвестно}" ;;
    esac
    KEEN_ABI=${architecture#*-}
}

download_package() {
    release_json="$TMP_DIR/release.json"
    fetch "$GITHUB_API/$PROJECT_REPOSITORY/releases/latest" "$release_json"
    RELEASE_TAG=$(tr ',' '\n' < "$release_json" \
        | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
        | head -n 1)
    case "$RELEASE_TAG" in
        ""|*[!A-Za-z0-9._-]*) die "GitHub вернул некорректный тег выпуска" ;;
    esac
    pattern="/keen-pbr_[^/]*_keenetic_${KEEN_ARCH}-${KEEN_ABI}\\.ipk$"
    package_url=$(github_asset_urls "$release_json" | grep -E "$pattern" | head -n 1 || true)
    [ -n "$package_url" ] || die "в Release нет полного пакета Keenetic для ${KEEN_ARCH}-${KEEN_ABI}"
    PACKAGE_FILE="$TMP_DIR/$(basename "$package_url")"
    fetch "$package_url" "$PACKAGE_FILE"

    sums_url=$(github_asset_urls "$release_json" | grep '/SHA256SUMS$' | head -n 1 || true)
    if [ -n "$sums_url" ]; then
        fetch "$sums_url" "$TMP_DIR/SHA256SUMS"
        expected=$(awk -v name="$(basename "$PACKAGE_FILE")" '$2 == name || $2 == "*" name { print $1; exit }' "$TMP_DIR/SHA256SUMS")
        [ -n "$expected" ] || die "пакет отсутствует в SHA256SUMS"
        actual=$(sha256sum "$PACKAGE_FILE" | awk '{print $1}')
        [ "$actual" = "$expected" ] || die "контрольная сумма пакета не совпадает"
    else
        die "в Release нет SHA256SUMS; непроверенный пакет устанавливаться не будет"
    fi
}

bootstrap_rescue_helpers() {
    payload="$TMP_DIR/data.tar.gz"
    helper_tree="$TMP_DIR/package-helpers"
    mkdir "$helper_tree" || die "не удалось подготовить каталог rescue helper"
    chmod 0700 "$helper_tree" || die "не удалось защитить каталог rescue helper"
    tar -xOf "$PACKAGE_FILE" ./data.tar.gz > "$payload" ||
        die "проверенный IPK не содержит data.tar.gz"
    [ -s "$payload" ] || die "data.tar.gz в проверенном IPK пуст"
    tar -xzf "$payload" -C "$helper_tree" \
        ./opt/usr/lib/keen-pbr/rescue-update.sh \
        ./opt/usr/lib/keen-pbr/rescue-startup-guard.sh \
        ./opt/usr/lib/keen-pbr/update-lock.sh ||
        die "проверенный IPK не содержит rescue helper"
    rescue_source="$helper_tree/opt/usr/lib/keen-pbr/rescue-update.sh"
    startup_guard_source="$helper_tree/opt/usr/lib/keen-pbr/rescue-startup-guard.sh"
    lock_source="$helper_tree/opt/usr/lib/keen-pbr/update-lock.sh"
    [ -f "$rescue_source" ] && [ ! -L "$rescue_source" ] &&
        [ -f "$startup_guard_source" ] &&
        [ ! -L "$startup_guard_source" ] &&
        [ -f "$lock_source" ] && [ ! -L "$lock_source" ] ||
        die "rescue helper в IPK имеет небезопасный тип"
    /bin/sh -n "$rescue_source" || die "получен повреждённый rescue helper"
    /bin/sh -n "$startup_guard_source" ||
        die "получен повреждённый startup guard"
    /bin/sh -n "$lock_source" || die "получен повреждённый update lock helper"

    [ ! -L "$RESCUE_DIR" ] &&
        { [ ! -e "$RESCUE_DIR" ] || [ -d "$RESCUE_DIR" ]; } ||
        die "каталог rescue имеет небезопасный тип"
    mkdir -p "$RESCUE_DIR"
    chmod 0700 "$RESCUE_DIR" || die "не удалось защитить каталог rescue"
    for helper in rescue-update.sh update-lock.sh; do
        source="$helper_tree/opt/usr/lib/keen-pbr/$helper"
        temporary="$RESCUE_DIR/$helper.tmp.$$"
        cp "$source" "$temporary" || die "не удалось подготовить $helper"
        chmod 0755 "$temporary" || die "не удалось выставить права $helper"
        mv -f "$temporary" "$RESCUE_DIR/$helper" ||
            die "не удалось установить $helper"
    done
    mkdir -p /opt/etc/init.d
    startup_guard_tmp="/opt/etc/init.d/S00keen-pbr-rescue.tmp.$$"
    cp "$startup_guard_source" "$startup_guard_tmp" ||
        die "не удалось подготовить ранний rescue guard"
    chmod 0755 "$startup_guard_tmp" ||
        die "не удалось выставить права раннего rescue guard"
    mv -f "$startup_guard_tmp" /opt/etc/init.d/S00keen-pbr-rescue ||
        die "не удалось установить ранний rescue guard"
    sync
    # Revalidate an inherited/fallback lock using the freshly installed common
    # implementation before any package or snapshot mutation. A no-op
    # ownership transfer also upgrades the bootstrap sidecars to the v2 atomic
    # owner record used for crash-safe hand-offs.
    "$LOCK_HELPER" held "$LOCK_OWNER_PID" "$LOCK_TOKEN" ||
        die "потеряна блокировка обновления"
    "$LOCK_HELPER" transfer "$LOCK_OWNER_PID" "$LOCK_TOKEN" \
        "$LOCK_OWNER_PID" >/dev/null ||
        die "не удалось перевести блокировку обновления в безопасный формат"
}

find_existing_sing_box() {
    for candidate in \
        /opt/bin/sing-box \
        /opt/sbin/sing-box \
        /opt/usr/bin/sing-box \
        /opt/etc/awg-manager/singbox/sing-box
    do
        if [ -x "$candidate" ] && "$candidate" version >/dev/null 2>&1; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    return 1
}

make_entware_sing_box_wrapper() {
    binary=$1
    real_binary="${binary}.real"
    loader=""
    for candidate in /opt/lib/ld-*.so*; do
        [ -e "$candidate" ] || continue
        loader=$candidate
        break
    done
    [ -n "$loader" ] || return 1

    mv "$binary" "$real_binary"
    cat > "$binary" <<EOF
#!/bin/sh
exec "$loader" --library-path /opt/lib:/opt/usr/lib "$real_binary" "\$@"
EOF
    chmod 0755 "$binary"
    if "$binary" version >/dev/null 2>&1; then
        return 0
    fi

    rm -f "$binary"
    mv "$real_binary" "$binary"
    return 1
}

sing_box_version() {
    "$1" version 2>/dev/null | awk 'NR == 1 { print $3; exit }'
}

latest_sing_box_version() {
    release_json="$TMP_DIR/sing-box-latest.json"
    fetch "$GITHUB_API/SagerNet/sing-box/releases/latest" "$release_json"
    grep '"tag_name"' "$release_json" | head -n 1 | cut -d '"' -f 4 | sed 's/^v//'
}

install_sing_box() {
    requested_version=$1
    case "$KEEN_ARCH" in
        aarch64) sing_arch="arm64" ;;
        armv7) sing_arch="armv7" ;;
        mipsel) sing_arch="mipsle" ;;
        mips) sing_arch="mips" ;;
        x64) sing_arch="amd64" ;;
        *) die "для архитектуры $KEEN_ARCH не задан официальный архив sing-box" ;;
    esac

    release_json="$TMP_DIR/sing-box-release-${requested_version}.json"
    fetch "$GITHUB_API/SagerNet/sing-box/releases/tags/v${requested_version}" "$release_json"
    archive_url=$(github_asset_urls "$release_json" | grep -E "/sing-box-${requested_version}-linux-${sing_arch}\\.tar\\.gz$" | head -n 1 || true)
    [ -n "$archive_url" ] || die "в официальном выпуске sing-box ${requested_version} нет архива linux-$sing_arch"
    archive="$TMP_DIR/$(basename "$archive_url")"
    fetch "$archive_url" "$archive"

    checksums_url=$(github_asset_urls "$release_json" | grep -E '/sing-box-[^/]+-checksums\\.txt$' | head -n 1 || true)
    if [ -n "$checksums_url" ]; then
        fetch "$checksums_url" "$TMP_DIR/sing-box-checksums.txt"
        expected=$(awk -v name="$(basename "$archive")" '$2 == name || $2 == "*" name { print $1; exit }' "$TMP_DIR/sing-box-checksums.txt")
        [ -n "$expected" ] || die "архив sing-box отсутствует в файле контрольных сумм"
        actual=$(sha256sum "$archive" | awk '{print $1}')
        [ "$actual" = "$expected" ] || die "контрольная сумма sing-box не совпадает"
    fi

    mkdir -p "$TMP_DIR/sing-box" /opt/bin /opt/etc/keen-pbr
    tar -xzf "$archive" -C "$TMP_DIR/sing-box"
    binary=$(find "$TMP_DIR/sing-box" -type f -name sing-box | head -n 1)
    [ -n "$binary" ] || die "исполняемый файл sing-box не найден в архиве"
    cp "$binary" /opt/bin/sing-box
    chmod 0755 /opt/bin/sing-box
    if ! /opt/bin/sing-box version >/dev/null 2>&1; then
        if ! make_entware_sing_box_wrapper /opt/bin/sing-box; then
            rm -f /opt/bin/sing-box /opt/bin/sing-box.real
            die "официальный sing-box не запускается с ABI установленного Entware"
        fi
    fi
    printf '%s\n' /opt/bin/sing-box > /opt/etc/keen-pbr/sing-box-managed.path
    SING_BOX_PATH=/opt/bin/sing-box
}

choose_sing_box() {
    existing=$(find_existing_sing_box || true)
    latest=$(latest_sing_box_version || true)
    [ -n "$latest" ] || latest="$SING_BOX_TESTED_VERSION"
    if [ -n "$existing" ]; then
        current=$(sing_box_version "$existing")
        say "Найден sing-box: $existing (версия ${current:-не определена})"
        say "  1) Использовать найденный файл (рекомендуется, если он уже проверен)"
        say "  2) Установить протестированную версию $SING_BOX_TESTED_VERSION в /opt/bin"
        say "  3) Установить последнюю версию $latest"
        say "  4) Указать другой существующий путь"
        say "  5) Продолжить без sing-box (только нативные интерфейсы)"
        if [ "$latest" != "$SING_BOX_TESTED_VERSION" ]; then
            say "ПРЕДУПРЕЖДЕНИЕ: версия $latest новее протестированной $SING_BOX_TESTED_VERSION; совместимость не проверялась."
        fi
        choice=$(ask "Выберите [1-5] (по умолчанию 1):" "1")
    else
        say "sing-box не найден в стандартных каталогах."
        say "  1) Установить протестированную версию $SING_BOX_TESTED_VERSION в /opt/bin (рекомендуется)"
        say "  2) Установить последнюю версию $latest"
        say "  3) Указать другой существующий путь"
        say "  4) Продолжить без sing-box (только нативные интерфейсы)"
        if [ "$latest" != "$SING_BOX_TESTED_VERSION" ]; then
            say "ПРЕДУПРЕЖДЕНИЕ: версия $latest новее протестированной $SING_BOX_TESTED_VERSION; совместимость не проверялась."
        fi
        choice=$(ask "Выберите [1-4] (по умолчанию 1):" "1")
        case "$choice" in 1) choice=2 ;; 2) choice=3 ;; 3) choice=4 ;; 4) choice=5 ;; *) die "неверный выбор" ;; esac
    fi

    case "$choice" in
        1) SING_BOX_PATH="$existing" ;;
        2) install_sing_box "$SING_BOX_TESTED_VERSION" ;;
        3)
            if [ "$latest" != "$SING_BOX_TESTED_VERSION" ]; then
                confirm=$(ask "Установить непроверенную версию $latest? [y/N]:" "N")
                case "$confirm" in y|Y|yes|YES|д|Д|да|ДА) ;; *) die "установка новой версии отменена" ;; esac
            fi
            install_sing_box "$latest"
            ;;
        4)
            SING_BOX_PATH=$(ask "Абсолютный путь к sing-box:" "")
            [ -x "$SING_BOX_PATH" ] || die "файл не является исполняемым: $SING_BOX_PATH"
            "$SING_BOX_PATH" version >/dev/null || die "выбранный sing-box не запускается"
            ;;
        5) SING_BOX_PATH="" ;;
        *) die "неверный выбор" ;;
    esac
}

set_sing_box_path() {
    [ -n "$SING_BOX_PATH" ] || return 0
    [ -f "$TRANSPORT_CONFIG" ] || die "конфигурация транспортов не установлена"
    escaped=$(printf '%s' "$SING_BOX_PATH" | sed 's/[\\&|]/\\&/g')
    sed -i "s|\"sing_box_binary\"[[:space:]]*:[[:space:]]*\"[^\"]*\"|\"sing_box_binary\": \"$escaped\"|" "$TRANSPORT_CONFIG"
    chmod 0600 "$TRANSPORT_CONFIG"
    /opt/etc/init.d/S79transport-manager restart
}

canonicalize_keenetic_auth_endpoint() {
    value=$1
    case "$value" in
        127.0.0.1)
            host=127.0.0.1
            port=80
            ;;
        127.0.0.1:*)
            host=127.0.0.1
            port=${value#127.0.0.1:}
            ;;
        '[::1]')
            host='[::1]'
            port=80
            ;;
        '[::1]:'*)
            host='[::1]'
            port=${value#'[::1]:'}
            ;;
        *)
            return 1
            ;;
    esac

    case "$port" in
        ''|*[!0-9]*) return 1 ;;
    esac
    # Strip leading zeroes without relying on shell arithmetic parsing octal.
    normalized_port=$(printf '%s\n' "$port" | sed 's/^0*//')
    [ -n "$normalized_port" ] || normalized_port=0
    [ "$normalized_port" -ge 1 ] 2>/dev/null || return 1
    [ "$normalized_port" -le 65535 ] 2>/dev/null || return 1

    CANONICAL_KEENETIC_AUTH_ENDPOINT="${host}:${normalized_port}"
    return 0
}

configure_web_auth() {
    auth_file=/opt/etc/keen-pbr/auth.json
    if [ -f "$auth_file" ]; then
        keep=$(ask "Сохранить существующие настройки авторизации веб-интерфейса? [Y/n]:" "Y")
        case "$keep" in
            n|N|no|NO) ;;
            *) return 0 ;;
        esac
    fi

    enable=$(ask "Включить защиту веб-интерфейса паролем? [Y/n]:" "Y")
    case "$enable" in
        n|N|no|NO)
            printf '%s\n' '{"enabled":false}' > "$auth_file"
            chmod 0600 "$auth_file"
            /opt/etc/init.d/S80keen-pbr restart
            return 0
            ;;
    esac

    say "Вход можно проверять учётной записью самого роутера — тогда отдельный пароль не нужен и не хранится."
    router_auth=$(ask "Использовать учётную запись роутера (Keenetic/Netcraze)? [Y/n]:" "Y")
    case "$router_auth" in
        n|N|no|NO) ;;
        *)
            endpoint=$(ask "Адрес веб-интерфейса роутера (по умолчанию 127.0.0.1:80):" "127.0.0.1:80")
            canonicalize_keenetic_auth_endpoint "$endpoint" ||
                die "разрешён только локальный адрес 127.0.0.1 или [::1] с портом 1..65535"
            umask 077
            printf '{"enabled":true,"provider":"keenetic","keenetic_endpoint":"%s","session_ttl_seconds":604800}\n' \
                "$CANONICAL_KEENETIC_AUTH_ENDPOINT" > "$auth_file"
            chmod 0600 "$auth_file"
            /opt/etc/init.d/S80keen-pbr restart
            say "Вход в keen-pbr-sb теперь выполняется логином и паролем администратора роутера."
            return 0
            ;;
    esac

    say "По возможности используйте отдельный пароль. Можно ввести реквизиты root Entware или администратора Keenetic, но keen-pbr-sb хранит и проверяет собственную локальную копию."
    username=$(ask "Логин веб-интерфейса (по умолчанию admin):" "admin")
    password=$(ask_secret "Пароль веб-интерфейса:")
    [ -n "$password" ] || die "пароль веб-интерфейса не может быть пустым"
    escaped_username=$(printf '%s' "$username" | sed 's/[\\"]/\\&/g')
    escaped_password=$(printf '%s' "$password" | sed 's/[\\"]/\\&/g')
    umask 077
    printf '{"enabled":true,"provider":"local","username":"%s","password":"%s","session_ttl_seconds":604800}\n' \
        "$escaped_username" "$escaped_password" > "$auth_file"
    chmod 0600 "$auth_file"
    /opt/etc/init.d/S80keen-pbr restart
}

configure_dns() {
    answer=$(ask "Включить Keenetic DNS Override и настроить dnsmasq Entware? [Y/n]:" "Y")
    case "$answer" in
        n|N|no|NO) return 0 ;;
    esac

    template=/opt/usr/lib/keen-pbr/dnsmasq.conf.template
    config=/opt/etc/dnsmasq.conf
    [ -f "$template" ] || die "шаблон dnsmasq отсутствует"
    /opt/sbin/dnsmasq --test --conf-file="$template" >/dev/null 2>&1 || die "сгенерированная конфигурация dnsmasq некорректна"
    backup="$config.backup-mykeenpbr-$(date +%Y%m%d%H%M%S)"
    [ ! -f "$config" ] || cp -p "$config" "$backup"

    cp "$template" "$config"
    chmod 0600 "$config"
    if ! ndmc -c "opkg dns-override" >/dev/null ||
       ! ndmc -c "system configuration save" >/dev/null; then
        [ ! -f "$backup" ] || cp -p "$backup" "$config"
        die "не удалось включить opkg dns-override"
    fi
    if ! /opt/etc/init.d/S56dnsmasq restart >/dev/null 2>&1; then
        [ ! -f "$backup" ] || cp -p "$backup" "$config"
        ndmc -c "no opkg dns-override" >/dev/null 2>&1 || true
        ndmc -c "system configuration save" >/dev/null 2>&1 || true
        die "dnsmasq не запустился; DNS Override отменён"
    fi
    if ! nslookup google.com 127.0.0.1 >/dev/null 2>&1; then
        say "ПРЕДУПРЕЖДЕНИЕ: dnsmasq запущен, но быстрая проверка внешнего DNS не прошла."
        say "Установка продолжится; проверьте состояние DNS и диагностику в веб-интерфейсе."
    fi
}

configure_nfqws2() {
    if /opt/bin/opkg status nfqws2-keenetic 2>/dev/null | grep -q '^Status:.* installed'; then
        answer=$(ask "nfqws2 уже установлен. Обновить его из официального репозитория? [y/N]:" "N")
    else
        answer=$(ask "Установить nfqws2 из официального репозитория nfqws/nfqws2-keenetic? [y/N]:" "N")
    fi
    case "$answer" in y|Y|yes|YES|д|Д|да|ДА) ;; *) return 0 ;; esac

    say "Подготавливаю HTTPS и официальный репозиторий nfqws2..."
    # Старый wget из Entware понимает только HTTP/FTP. Сначала обновляем
    # обычные feeds и заменяем его на SSL-вариант, и только после этого
    # добавляем HTTPS-feed nfqws2. Удаление feed также чинит повторный запуск
    # после ранее прерванной установки.
    mkdir -p /opt/etc/opkg
    rm -f /opt/etc/opkg/nfqws2-keenetic.conf
    /opt/bin/opkg update || die "не удалось обновить список пакетов Entware"
    /opt/bin/opkg install ca-certificates wget-ssl || die "не удалось установить HTTPS-зависимости nfqws2"
    /opt/bin/opkg remove wget-nossl >/dev/null 2>&1 || true
    printf '%s\n' 'src/gz nfqws2-keenetic https://nfqws.github.io/nfqws2-keenetic/all' > /opt/etc/opkg/nfqws2-keenetic.conf
    /opt/bin/opkg update || die "не удалось загрузить официальный репозиторий nfqws2"
    say "Устанавливаю пакет nfqws2..."
    if /opt/bin/opkg status nfqws2-keenetic 2>/dev/null | grep -q '^Status:.* installed'; then
        /opt/bin/opkg upgrade nfqws2-keenetic || die "не удалось обновить nfqws2"
    else
        /opt/bin/opkg install nfqws2-keenetic || die "не удалось установить nfqws2"
    fi
    say "nfqws2 установлен. Управление доступно в разделе «nfqws2» веб-интерфейса keen-pbr-sb."
}

install_package_transactionally() {
    [ ! -L "$RESCUE_DIR" ] &&
        { [ ! -e "$RESCUE_DIR" ] || [ -d "$RESCUE_DIR" ]; } ||
        die "каталог rescue имеет небезопасный тип"
    mkdir -p "$RESCUE_DIR"
    chmod 0700 "$RESCUE_DIR" ||
        die "не удалось защитить каталог rescue"
    [ -x "$RESCUE_HELPER" ] ||
        die "rescue helper не установлен"
    "$RESCUE_HELPER" stage "$PACKAGE_FILE"

    if KEEN_PBR_RESCUE_TRANSACTION=1 \
           KEEN_PBR_REPLACE_DNSMASQ_DEFAULTS=N \
           /opt/bin/opkg --force-reinstall install "$PACKAGE_FILE" &&
       [ -x "$RESCUE_HELPER" ] &&
       "$RESCUE_HELPER" verify; then
        if "$RESCUE_HELPER" promote; then
            return 0
        fi
        say "ОШИБКА: пакет работает, но rescue-снимок не удалось зафиксировать."
    fi

    say "ОШИБКА: новый пакет не прошёл проверку после установки."
    if [ -x "$RESCUE_HELPER" ] &&
       "$RESCUE_HELPER" rollback-candidate; then
        say "Предыдущий IPK автоматически восстановлен."
    else
        say "Автоматический IPK-откат пока недоступен; сохранён бэкап конфигурации."
    fi
    return 1
}

repair_interrupted_nfqws_bootstrap() {
    feed=/opt/etc/opkg/nfqws2-keenetic.conf
    [ -f "$feed" ] || return 0
    if /opt/bin/opkg status wget-ssl 2>/dev/null | grep -q '^Status:.* installed'; then
        return 0
    fi
    say "Обнаружена незавершённая настройка nfqws2. Сначала восстанавливаю поддержку HTTPS..."
    saved_feed="$TMP_DIR/nfqws2-keenetic.conf"
    mv "$feed" "$saved_feed"
    /opt/bin/opkg update || die "не удалось обновить пакеты Entware при восстановлении HTTPS"
    /opt/bin/opkg install ca-certificates wget-ssl || die "не удалось установить wget с поддержкой HTTPS"
    /opt/bin/opkg remove wget-nossl >/dev/null 2>&1 || true
    mv "$saved_feed" "$feed"
}

[ "$(id -u)" = "0" ] || die "запустите установщик от пользователя root"
TMP_BASE=${TMPDIR:-/tmp}
case "$TMP_BASE" in
    /*) ;;
    *) die "TMPDIR должен быть абсолютным путём" ;;
esac
[ "$TMP_BASE" != "/" ] || die "TMPDIR не должен указывать на корневой каталог"
TMP_DIR=$(mktemp -d "$TMP_BASE/mykeenpbr-install.XXXXXX") ||
    die "не удалось создать защищённый временный каталог"
case "$TMP_DIR" in
    "$TMP_BASE"/mykeenpbr-install.*) ;;
    *) die "mktemp вернул небезопасный путь" ;;
esac
chmod 0700 "$TMP_DIR" || die "не удалось защитить временный каталог"
acquire_update_lock || die "другое обновление или откат keen-pbr-sb уже выполняется"
detect_target
say "Установка keen-pbr-sb для ${KEEN_ARCH}-${KEEN_ABI} из $PROJECT_REPOSITORY"
download_package
bootstrap_rescue_helpers
if [ "$UPDATE_ONLY" = "1" ]; then
    say "Устанавливаю обновление keen-pbr-sb без изменения пользовательских настроек..."
    install_package_transactionally
    say "Обновление keen-pbr-sb установлено. Веб-интерфейс перезапускается."
    exit 0
fi
choose_sing_box
repair_interrupted_nfqws_bootstrap
/opt/bin/opkg update
install_package_transactionally
set_sing_box_path
configure_web_auth
configure_dns
configure_nfqws2

say ""
say "Установка завершена."
say "Веб-интерфейс: http://my.keenetic.net:12121/"
say "Каталог конфигурации и резервных копий: /opt/etc/keen-pbr"

#!/bin/sh

set -eu
umask 077

PROJECT_REPOSITORY="${MYKEENPBR_REPOSITORY:-blindtechnique/keen-pbr-sb}"
TRUSTED_RELEASE_REPOSITORY="blindtechnique/keen-pbr-sb"
GITHUB_API="https://api.github.com/repos"
STABLE_RELEASE_TAG='v3.3.2-sb.12'
SING_BOX_PINNED_VERSION="1.13.14"
TMP_DIR=
TRANSPORT_CONFIG="/opt/etc/keen-pbr/transports.json"
RESCUE_DIR="/opt/var/lib/keen-pbr/rescue"
RESCUE_HELPER="$RESCUE_DIR/rescue-update.sh"
LOCK_HELPER="$RESCUE_DIR/update-lock.sh"
METADATA_HELPER="$RESCUE_DIR/portable-stat.sh"
LOCK_DIR="/opt/var/run/keen-pbr-update.lock"
UPDATE_ONLY=0
AUTH_SETUP_ONLY=0
REQUESTED_RELEASE_TAG=${KEEN_PBR_UPDATE_RELEASE_TAG:-}
# This one-shot handoff must not leak through opkg/postinst into new services.
unset KEEN_PBR_UPDATE_RELEASE_TAG
LOCK_OWNER_PID=${KEEN_PBR_UPDATE_LOCK_PID:-}
LOCK_TOKEN=${KEEN_PBR_UPDATE_LOCK_TOKEN:-}
LOCK_OWNED=0
LOCK_RETURN_PID=
LOCK_HELPER_V2=0
FALLBACK_CLEANUP_OWNED=0
DNS_SETUP_CHOICE=
NFQWS_SETUP_CHOICE=
DNS_BOOTSTRAP=0
DNS_INSTALL_ROLLBACK=0
FIRST_PACKAGE_STARTED=0
RESUME_FIRST_INSTALL=0
INSTALL_LANGUAGE=${KEEN_PBR_INSTALL_LANGUAGE:-ru}

for argument in "$@"; do
    case "$argument" in
        --update) UPDATE_ONLY=1 ;;
        --configure-auth) AUTH_SETUP_ONLY=1 ;;
        *) printf '%s\n' "ОШИБКА / ERROR: неизвестный параметр / unknown argument: $argument" >&2; exit 2 ;;
    esac
done

if [ "$AUTH_SETUP_ONLY" = 1 ] && [ "$UPDATE_ONLY" = 1 ]; then
    printf '%s\n' 'ОШИБКА / ERROR: --configure-auth и / and --update несовместимы / cannot be combined.' >&2
    exit 2
fi

# stable11 downloads this source through its release tag but passes only
# --update. Keep that legacy handoff on this release even if Latest changes;
# modern signed updaters already pass the exact verified tag explicitly.
if [ "$UPDATE_ONLY" = "1" ] && [ -z "$REQUESTED_RELEASE_TAG" ]; then
    REQUESTED_RELEASE_TAG=$STABLE_RELEASE_TAG
fi

cleanup() {
    status=$?
    if [ "${DNS_INSTALL_ROLLBACK:-0}" = 1 ]; then
        # First-install DNS was prepared before postinst. If installation did
        # not complete, return port 53 and the old config to their prior owner.
        if [ "${FIRST_PACKAGE_STARTED:-0}" = 1 ] &&
           [ -x /opt/etc/init.d/S80keen-pbr ]; then
            /opt/etc/init.d/S80keen-pbr stop >/dev/null 2>&1 || true
        fi
        restore_dns_setup "$INSTALL_DNS_OVERRIDE" "$INSTALL_DNS_RUNNING" \
            "$INSTALL_DNS_CONFIG" "$INSTALL_DNS_BACKUP" \
            "$INSTALL_DNS_HAD_CONFIG" "$INSTALL_DNS_RESTARTED" || {
                say "Не удалось полностью вернуть прежний DNS. Резервная копия: $INSTALL_DNS_BACKUP" "Could not fully restore previous DNS settings. Backup: $INSTALL_DNS_BACKUP" >&2
                status=1
            }
    fi
    # A failed HTTPS bootstrap must not discard the user's original feed with
    # the temporary downloads (including an interruption during opkg).
    if [ -n "${NFQWS_SAVED_FEED:-}" ] &&
       { [ -e "$NFQWS_SAVED_FEED" ] || [ -L "$NFQWS_SAVED_FEED" ]; }; then
        if mv "$NFQWS_SAVED_FEED" /opt/etc/opkg/nfqws2-keenetic.conf; then
            NFQWS_SAVED_FEED=
        else
            say "Не удалось вернуть источник nfqws2. Копия сохранена: $NFQWS_SAVED_FEED" "Could not restore the nfqws2 feed. A copy is retained at: $NFQWS_SAVED_FEED" >&2
            TMP_DIR=
            status=1
        fi
    fi
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
    trap - EXIT INT TERM HUP
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM
trap 'exit 129' HUP

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
       [ -f "$METADATA_HELPER" ] && [ ! -L "$METADATA_HELPER" ] &&
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
    if [ "${INSTALL_LANGUAGE:-ru}" = en ]; then
        printf '%s\n' "${2:-$1}"
    else
        printf '%s\n' "$1"
    fi
}

die() {
    say "ОШИБКА: $1" "ERROR: ${2:-$1}" >&2
    exit 1
}

choose_install_language() {
    # Web updates have no controlling terminal and never ask interactive questions.
    [ "$UPDATE_ONLY" = 0 ] || return 0
    while :; do
        language_choice=$(ask 'Язык / Language: 1 — Русский, 2 — English [1/2]:' '1')
        case "$language_choice" in
            1|ru|RU) INSTALL_LANGUAGE=ru; return 0 ;;
            2|en|EN) INSTALL_LANGUAGE=en; return 0 ;;
        esac
        printf '%s\n' 'Введите 1 или 2 / Enter 1 or 2.' >&2
    done
}

# Единственный способ звать Keenetic CLI из этого скрипта.
#
# ndmc линкуется с библиотеками прошивки, а Entware держит собственную glibc в
# /opt/lib. Унаследованный LD_LIBRARY_PATH заставляет загрузчик подсунуть ndmc
# чужую libc, и он умирает до выполнения команды:
#
#     ndm: ndmc: system failed [0xcffd0062].
#     Cli::Main: failed to initialize.
#
# Переменная чистится только для дочернего процесса. Диагностику ndmc пишет в
# stdout, а не в stderr, поэтому её нельзя просто отправить в /dev/null вместе
# с обычным выводом: она сохраняется и печатается ровно при ошибке.
run_ndmc() {
    ndmc_output="$(LD_LIBRARY_PATH= ndmc -c "$1" 2>&1)" && return 0
    ndmc_status=$?
    say "Keenetic CLI не выполнил '$1':" "Keenetic CLI failed to execute '$1':" >&2
    printf '%s\n' "$ndmc_output" >&2
    return "$ndmc_status"
}

ask() {
    prompt="$1"
    default="$2"
    [ "${INSTALL_LANGUAGE:-ru}" != en ] || prompt="${3:-$1}"
    printf '%s ' "$prompt" >/dev/tty
    answer=""
    IFS= read -r answer </dev/tty || true
    [ -n "$answer" ] || answer="$default"
    printf '%s' "$answer"
}

ask_secret() {
    prompt="$1"
    [ "${INSTALL_LANGUAGE:-ru}" != en ] || prompt="${2:-$1}"
    printf '%s ' "$prompt" >/dev/tty
    stty -echo </dev/tty 2>/dev/null || true
    answer=""
    read_status=0
    IFS= read -r answer </dev/tty || read_status=$?
    stty echo </dev/tty 2>/dev/null || true
    printf '\n' >/dev/tty
    printf '%s' "$answer"
    return "$read_status"
}

fetch() {
    url="$1"
    output="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --connect-timeout 15 --max-time 180 \
            --retry 3 -o "$output" "$url"
    elif [ -x /opt/bin/curl ]; then
        /opt/bin/curl -fsSL --connect-timeout 15 --max-time 180 \
            --retry 3 -o "$output" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -T 60 -O "$output" "$url"
    else
        die "требуется curl или wget" "curl or wget is required"
    fi
}

github_asset_urls() {
    # Tolerate both pretty-printed and compact GitHub API responses.
    tr ',' '\n' < "$1" \
        | sed -n 's/.*"browser_download_url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'
}

detect_target() {
    [ -x /opt/bin/opkg ] || die "Entware не подключён в /opt" "Entware is not mounted at /opt"
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
        *) die "неподдерживаемая архитектура Entware: ${architecture:-неизвестно}" "unsupported Entware architecture: ${architecture:-unknown}" ;;
    esac
    KEEN_ABI=${architecture#*-}
}

# BEGIN GENERATED RELEASE VERIFIER - DO NOT EDIT
# Generated by build_scripts/embed-release-verifier.py.
# First-install trust comes from this installer, not downloaded metadata.
prepare_release_verifier() {
    RELEASE_VERIFIER="$TMP_DIR/release-verify.sh"
    RELEASE_PUBLIC_KEY="$TMP_DIR/release-public.pem"
    cat > "$RELEASE_VERIFIER" <<'KEEN_PBR_RELEASE_VERIFIER_EOF'
#!/bin/sh
# Standalone verification before any downloaded installer/package is executed.
# The caller supplies an already trusted public key, never a downloaded one.
set -eu
LC_ALL=C
export LC_ALL

release_verify_fail() {
    printf '%s\n' "Release verification failed: $*" >&2
    exit 1
}

[ "$#" -eq 11 ] || release_verify_fail 'invalid arguments'
rv_manifest=$1
rv_signature=$2
rv_key=$3
rv_repository=$4
rv_channel=$5
rv_release=$6
rv_kind=$7
rv_arch=$8
rv_abi=$9
shift 9
rv_filename=$1
rv_localfile=$2

# Restrict context before passing it through awk -v (which interprets escapes).
case "$rv_repository" in ''|*[!A-Za-z0-9_./-]*) release_verify_fail 'invalid repository' ;; esac
case "$rv_channel" in stable|alpha|beta|next) ;; *) release_verify_fail 'invalid channel' ;; esac
case "$rv_release" in ''|*[!A-Za-z0-9._-]*) release_verify_fail 'invalid release' ;; esac
case "$rv_kind" in installer|package) ;; *) release_verify_fail 'invalid file kind' ;; esac
case "$rv_arch" in any|aarch64|armv7|mipsel|mips|x64) ;; *) release_verify_fail 'invalid architecture' ;; esac
case "$rv_abi" in ''|*[!0-9.a-z]*) release_verify_fail 'invalid ABI' ;; esac
case "$rv_filename" in ''|*[!A-Za-z0-9._+-]*) release_verify_fail 'invalid filename' ;; esac

# Prevent an option-like relative path from being interpreted by OpenSSL.
case "$rv_manifest" in /*|./*|../*) ;; *) rv_manifest=./$rv_manifest ;; esac
case "$rv_signature" in /*|./*|../*) ;; *) rv_signature=./$rv_signature ;; esac
case "$rv_key" in /*|./*|../*) ;; *) rv_key=./$rv_key ;; esac
case "$rv_localfile" in /*|./*|../*) ;; *) rv_localfile=./$rv_localfile ;; esac
for rv_input in "$rv_manifest" "$rv_signature" "$rv_key" "$rv_localfile"; do
    [ -f "$rv_input" ] && [ -r "$rv_input" ] || release_verify_fail 'a required file is unavailable'
done
rv_bytes=$(wc -c < "$rv_manifest")
[ "$rv_bytes" -gt 0 ] && [ "$rv_bytes" -le 65536 ] || release_verify_fail 'manifest size is invalid'
rv_bytes=$(wc -c < "$rv_signature")
[ "$rv_bytes" -eq 384 ] || release_verify_fail 'signature size is invalid'
# The marker keeps command substitution from stripping the final LF. Keenetic's
# small od applet does not support -A/-t; no byte-dump options are needed here.
rv_last_byte=$(tail -c 1 "$rv_manifest"; printf '.')
[ "$rv_last_byte" = "$(printf '\n.')" ] || release_verify_fail 'manifest must end with LF'

if [ -x /opt/bin/openssl ]; then
    rv_openssl=/opt/bin/openssl
elif command -v openssl >/dev/null 2>&1; then
    rv_openssl=$(command -v openssl)
else
    release_verify_fail 'OpenSSL is unavailable'
fi
"$rv_openssl" dgst -sha256 -verify "$rv_key" -sigopt rsa_padding_mode:pkcs1 \
    -signature "$rv_signature" "$rv_manifest" \
    >/dev/null 2>&1 || release_verify_fail 'signature is invalid'

rv_expected=$(awk -F '\t' \
    -v repository="$rv_repository" -v channel="$rv_channel" -v release="$rv_release" \
    -v kind="$rv_kind" -v arch="$rv_arch" -v abi="$rv_abi" -v filename="$rv_filename" '
function fail() { invalid = 1; exit 1 }
function token(value) {
    return length(value) <= 128 && value ~ /^[A-Za-z0-9][A-Za-z0-9._-]*$/
}
function hex(value, size) {
    return length(value) == size && value ~ /^[0-9a-f]+$/
}
index($0, "\r") { fail() }
NR == 1 { if (NF != 1 || $0 != "keen-pbr-release-v1") fail(); next }
NR == 2 {
    if (NF != 2 || $1 != "repository" || length($2) > 160 ||
        $2 !~ /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/ || $2 != repository) fail()
    next
}
NR == 3 { if (NF != 2 || $1 != "channel" || $2 != channel) fail(); next }
NR == 4 { if (NF != 2 || $1 != "release" || !token($2) || $2 != release) fail(); next }
NR == 5 { if (NF != 2 || $1 != "source" || !hex($2, 40)) fail(); next }
NR == 6 { if (NF != 2 || $1 != "build" || !token($2)) fail(); next }
{
    if (NF != 7 || $1 != "file" || ++files > 32 || !hex($6, 64) ||
        length($7) > 255 || $7 !~ /^[A-Za-z0-9][A-Za-z0-9._+-]*$/ || names[$7]++) fail()
    if ($2 == "installer") {
        if ($3 != "any" || $4 != "any" || $5 != "-" || $7 != "install.sh" || ++installers > 1) fail()
    } else if ($2 == "package") {
        if ($3 !~ /^(aarch64|armv7|mipsel|mips|x64)$/ || $4 !~ /^[0-9]+(\.[0-9]+)*$/ ||
            length($5) > 128 || $5 !~ /^[A-Za-z0-9][A-Za-z0-9._+-]*$/ ||
            $7 != "keen-pbr_" $5 "_keenetic_" $3 "-" $4 ".ipk" || targets[$3 "/" $4]++) fail()
        packages++
    } else fail()
    if ($2 == kind && $3 == arch && $4 == abi && $7 == filename) {
        selected++
        expected = $6
    }
}
END {
    if (invalid || installers != 1 || packages < 1 || selected != 1) exit 1
    print expected
}' "$rv_manifest") || release_verify_fail 'manifest context or file inventory is invalid'

if command -v sha256sum >/dev/null 2>&1; then
    rv_actual=$(sha256sum "$rv_localfile") || release_verify_fail 'file hashing failed'
elif command -v busybox >/dev/null 2>&1; then
    rv_actual=$(busybox sha256sum "$rv_localfile") || release_verify_fail 'file hashing failed'
else
    release_verify_fail 'SHA256 is unavailable'
fi
rv_actual=${rv_actual%% *}
[ "$rv_actual" = "$rv_expected" ] || release_verify_fail 'file checksum does not match the signed manifest'
KEEN_PBR_RELEASE_VERIFIER_EOF
    cat > "$RELEASE_PUBLIC_KEY" <<'KEEN_PBR_RELEASE_PUBLIC_KEY_EOF'
-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA4+cpJIu8nvU3ni9o3J7D
Om9Xue6O8bWlzlleXPMo+16r90Os+It3t0/AH8tVubqdw5bOlx/M56Q0fqsIo32k
EbATeTwgYQzz9pGMTJjIbC9zw9iNGCtZMC+tJNyfmQFBztH79O+/46iU7U+5gz+K
M/2rH7BB2NP04nfuL10e1F4RWXSNQaGIp1yajIvhfhrOWU9pcTIVJxdiJkDxpBEA
dBQBvn2dOVjJ2p2jhzy0CqHWJaDo26y5PD9UyqfgWyc999DVMm7Xif2tk/5K1DBR
ZoHeNVTkQVBfnINOojzo0wcUkrt/rtnV8rAFEqCQ6QK7wj/ZznSiwfIzdIYsfmXE
thc067ghulA1sou4mSs6tkVsW6kjA8xxQZE+9jO/9c/oaDDkFSpXFkSVcisKBEZV
+e6olBaKGZ7m0wY8F1x3NRTPqJ5cmJZjarMIZdJu22+WifjAGccSx9BptYYps203
FynD6xz2kiQzCrvSO1K5m/wbN9Vzx4EincGUF51h7IHtAgMBAAE=
-----END PUBLIC KEY-----
KEEN_PBR_RELEASE_PUBLIC_KEY_EOF
    chmod 0600 "$RELEASE_VERIFIER" "$RELEASE_PUBLIC_KEY"
}
# END GENERATED RELEASE VERIFIER

ensure_release_verifier() {
    [ "$PROJECT_REPOSITORY" = "$TRUSTED_RELEASE_REPOSITORY" ] ||
        die "Этот установщик проверяет только выпуски blindtechnique/keen-pbr-sb. Для другого проекта нужен его доверенный установщик." "This installer verifies releases from blindtechnique/keen-pbr-sb only. Use the trusted installer for any other project."
    if ! command -v openssl >/dev/null 2>&1 && [ ! -x /opt/bin/openssl ]; then
        # The unsigned stable11 updater enters this installer with --update
        # before openssl-util was a package dependency. Establish that local
        # verifier dependency from Entware before downloading/checking the IPK;
        # the signed self-updater still requires its packaged dependency first.
        say "Устанавливаю OpenSSL для проверки подписи пакета..." "Installing OpenSSL to verify the package signature..."
        /opt/bin/opkg update && /opt/bin/opkg install openssl-util ||
            die "Не удалось установить OpenSSL для проверки подписи. Установка keen-pbr-sb не началась." "Could not install OpenSSL for signature verification. keen-pbr-sb installation has not started."
    fi
    prepare_release_verifier
}


download_package() {
    [ "$PROJECT_REPOSITORY" = "$TRUSTED_RELEASE_REPOSITORY" ] ||
        die "Этот установщик проверяет только выпуски blindtechnique/keen-pbr-sb. Для другого проекта нужен его доверенный установщик." "This installer verifies releases from blindtechnique/keen-pbr-sb only. Use the trusted installer for any other project."
    release_json="$TMP_DIR/release.json"
    release_url="$GITHUB_API/$PROJECT_REPOSITORY/releases/latest"
    if [ -n "$REQUESTED_RELEASE_TAG" ]; then
        case "$REQUESTED_RELEASE_TAG" in
            *[!A-Za-z0-9._-]*) die "Получен некорректный тег обновления. Пакет не загружен; повторите проверку обновлений." "Invalid update tag. The package was not downloaded; check for updates again." ;;
        esac
        release_url="$GITHUB_API/$PROJECT_REPOSITORY/releases/tags/$REQUESTED_RELEASE_TAG"
    fi
    fetch "$release_url" "$release_json"
    RELEASE_TAG=$(tr ',' '\n' < "$release_json" \
        | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
        | head -n 1)
    case "$RELEASE_TAG" in
        ""|*[!A-Za-z0-9._-]*) die "GitHub вернул некорректный тег выпуска" "GitHub returned an invalid release tag" ;;
    esac
    if [ -n "$REQUESTED_RELEASE_TAG" ] && [ "$RELEASE_TAG" != "$REQUESTED_RELEASE_TAG" ]; then
        die "GitHub вернул другой выпуск. Пакет не загружен; повторите проверку обновлений." "GitHub returned a different release. The package was not downloaded; check for updates again."
    fi
    pattern="/keen-pbr_[^/]*_keenetic_${KEEN_ARCH}-${KEEN_ABI}\\.ipk$"
    package_url=$(github_asset_urls "$release_json" | grep -E "$pattern" | head -n 1 || true)
    [ -n "$package_url" ] || die "в Release нет полного пакета Keenetic для ${KEEN_ARCH}-${KEEN_ABI}" "the release has no full Keenetic package for ${KEEN_ARCH}-${KEEN_ABI}"
    PACKAGE_FILE="$TMP_DIR/$(basename "$package_url")"
    fetch "$package_url" "$PACKAGE_FILE"

    sums_url=$(github_asset_urls "$release_json" | grep '/SHA256SUMS$' | head -n 1 || true)
    if [ -n "$sums_url" ]; then
        fetch "$sums_url" "$TMP_DIR/SHA256SUMS"
        expected=$(awk -v name="$(basename "$PACKAGE_FILE")" '$2 == name || $2 == "*" name { print $1; exit }' "$TMP_DIR/SHA256SUMS")
        [ -n "$expected" ] || die "пакет отсутствует в SHA256SUMS" "the package is missing from SHA256SUMS"
        actual=$(sha256sum "$PACKAGE_FILE" | awk '{print $1}')
        [ "$actual" = "$expected" ] || die "контрольная сумма пакета не совпадает" "the package checksum does not match"
    else
        die "в Release нет SHA256SUMS; непроверенный пакет устанавливаться не будет" "the release has no SHA256SUMS; the unverified package will not be installed"
    fi

    release_base="https://github.com/$TRUSTED_RELEASE_REPOSITORY/releases/download/$RELEASE_TAG"
    fetch "$release_base/release-manifest.tsv" "$TMP_DIR/release-manifest.tsv"
    fetch "$release_base/release-manifest.sig" "$TMP_DIR/release-manifest.sig"
    /bin/sh "$RELEASE_VERIFIER" "$TMP_DIR/release-manifest.tsv" \
        "$TMP_DIR/release-manifest.sig" "$RELEASE_PUBLIC_KEY" \
        "$TRUSTED_RELEASE_REPOSITORY" stable "$RELEASE_TAG" \
        package "$KEEN_ARCH" "$KEEN_ABI" "$(basename "$PACKAGE_FILE")" "$PACKAGE_FILE" ||
        die "Подпись пакета не подтверждена. Установка не началась; попробуйте загрузить выпуск позднее." "Package signature verification failed. Installation has not started; try downloading the release later."
}

bootstrap_rescue_helpers() {
    payload="$TMP_DIR/data.tar.gz"
    helper_tree="$TMP_DIR/package-helpers"
    mkdir "$helper_tree" || die "не удалось подготовить каталог rescue helper" "could not prepare the recovery helper directory"
    chmod 0700 "$helper_tree" || die "не удалось защитить каталог rescue helper" "could not set permissions on the recovery helper directory"
    # BusyBox tar needs explicit gzip mode for the Entware IPK outer archive.
    tar -xzOf "$PACKAGE_FILE" ./data.tar.gz > "$payload" ||
        die "проверенный IPK не содержит data.tar.gz" "the verified IPK has no data.tar.gz"
    [ -s "$payload" ] || die "data.tar.gz в проверенном IPK пуст" "data.tar.gz is empty in the verified IPK"
    tar -xzf "$payload" -C "$helper_tree" \
        ./opt/usr/lib/keen-pbr/portable-stat.sh \
        ./opt/usr/lib/keen-pbr/rescue-update.sh \
        ./opt/usr/lib/keen-pbr/rescue-startup-guard.sh \
        ./opt/usr/lib/keen-pbr/update-lock.sh ||
        die "проверенный IPK не содержит rescue helper" "the verified IPK has no recovery helper"
    rescue_source="$helper_tree/opt/usr/lib/keen-pbr/rescue-update.sh"
    startup_guard_source="$helper_tree/opt/usr/lib/keen-pbr/rescue-startup-guard.sh"
    lock_source="$helper_tree/opt/usr/lib/keen-pbr/update-lock.sh"
    metadata_source="$helper_tree/opt/usr/lib/keen-pbr/portable-stat.sh"
    [ -f "$rescue_source" ] && [ ! -L "$rescue_source" ] &&
        [ -f "$startup_guard_source" ] &&
        [ ! -L "$startup_guard_source" ] &&
        [ -f "$lock_source" ] && [ ! -L "$lock_source" ] &&
        [ -f "$metadata_source" ] && [ ! -L "$metadata_source" ] ||
        die "rescue helper в IPK имеет небезопасный тип" "the recovery helper in the IPK is not a regular file"
    # Some Keenetic firmware shells reject -n. Prefer Entware's POSIX shell,
    # and probe syntax-check support before attributing failure to a helper.
    rescue_syntax_shell=""
    for rescue_shell_candidate in /opt/bin/sh /opt/bin/ash /bin/sh /bin/ash; do
        if [ -x "$rescue_shell_candidate" ] &&
            "$rescue_shell_candidate" -n -c ':' >/dev/null 2>&1; then
            rescue_syntax_shell="$rescue_shell_candidate"
            break
        fi
    done
    [ -n "$rescue_syntax_shell" ] ||
        die "не найдена оболочка для проверки синтаксиса; файлы восстановления не изменены" "no shell is available to check syntax; recovery files were not changed"
    "$rescue_syntax_shell" -n "$rescue_source" || die "получен повреждённый rescue helper" "the recovery helper has invalid shell syntax"
    "$rescue_syntax_shell" -n "$startup_guard_source" ||
        die "получен повреждённый startup guard" "the startup guard has invalid shell syntax"
    "$rescue_syntax_shell" -n "$lock_source" || die "получен повреждённый update lock helper" "the update lock helper has invalid shell syntax"
    "$rescue_syntax_shell" -n "$metadata_source" ||
        die "получен повреждённый metadata helper" "the metadata helper has invalid shell syntax"

    [ ! -L "$RESCUE_DIR" ] &&
        { [ ! -e "$RESCUE_DIR" ] || [ -d "$RESCUE_DIR" ]; } ||
        die "каталог rescue имеет небезопасный тип" "the recovery path is not a regular directory"
    mkdir -p "$RESCUE_DIR"
    chmod 0700 "$RESCUE_DIR" || die "не удалось защитить каталог rescue" "could not set permissions on the recovery directory"
    for helper in portable-stat.sh rescue-update.sh update-lock.sh; do
        source="$helper_tree/opt/usr/lib/keen-pbr/$helper"
        temporary="$RESCUE_DIR/$helper.tmp.$$"
        cp "$source" "$temporary" || die "не удалось подготовить $helper" "could not prepare $helper"
        chmod 0755 "$temporary" || die "не удалось выставить права $helper" "could not set permissions for $helper"
        mv -f "$temporary" "$RESCUE_DIR/$helper" ||
            die "не удалось установить $helper" "could not install $helper"
    done
    mkdir -p /opt/etc/init.d
    startup_guard_tmp="/opt/etc/init.d/S00keen-pbr-rescue.tmp.$$"
    cp "$startup_guard_source" "$startup_guard_tmp" ||
        die "не удалось подготовить ранний rescue guard" "could not prepare the early recovery guard"
    chmod 0755 "$startup_guard_tmp" ||
        die "не удалось выставить права раннего rescue guard" "could not set permissions for the early recovery guard"
    mv -f "$startup_guard_tmp" /opt/etc/init.d/S00keen-pbr-rescue ||
        die "не удалось установить ранний rescue guard" "could not install the early recovery guard"
    sync
    # Revalidate an inherited/fallback lock using the freshly installed common
    # implementation before any package or snapshot mutation. A no-op
    # ownership transfer also upgrades the bootstrap sidecars to the v2 atomic
    # owner record used for crash-safe hand-offs.
    "$LOCK_HELPER" held "$LOCK_OWNER_PID" "$LOCK_TOKEN" ||
        die "потеряна блокировка обновления" "the update lock was lost"
    "$LOCK_HELPER" transfer "$LOCK_OWNER_PID" "$LOCK_TOKEN" \
        "$LOCK_OWNER_PID" >/dev/null ||
        die "не удалось перевести блокировку обновления в безопасный формат" "could not migrate the update lock format"
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

    mv "$binary" "$real_binary" || return 1
    cat > "$binary" <<EOF || return 1
#!/bin/sh
exec "$loader" --library-path /opt/lib:/opt/usr/lib "\$0.real" "\$@"
EOF
    chmod 0755 "$binary" || return 1
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

publish_sing_box_candidate() {
    (
        # Test on /opt (the download directory may be mounted noexec). Until
        # this candidate works, neither executable of an existing pair changes.
        sb_stage=$(mktemp -d /opt/bin/.keen-pbr-sing-box.XXXXXX) || exit 1
        sb_publish_started=0
        sb_committed=0
        sb_wrapped=0
        cleanup_sing_box_candidate() {
            sb_status=$?
            sb_restore_failed=0
            if [ "$sb_publish_started" = 1 ] && [ "$sb_committed" = 0 ]; then
                for sb_name in sing-box.real sing-box; do
                    if [ -e "$sb_stage/old-$sb_name" ] || [ -L "$sb_stage/old-$sb_name" ]; then
                        mv -f "$sb_stage/old-$sb_name" "/opt/bin/$sb_name" || sb_restore_failed=1
                    else
                        rm -f "/opt/bin/$sb_name" || sb_restore_failed=1
                    fi
                done
            fi
            if [ "$sb_restore_failed" = 0 ]; then
                rm -rf "$sb_stage"
            else
                say "Не удалось вернуть sing-box. Предыдущие файлы сохранены: $sb_stage" "Could not restore sing-box. Previous files were retained at: $sb_stage" >&2
                sb_status=1
            fi
            trap - EXIT INT TERM HUP
            exit "$sb_status"
        }
        trap cleanup_sing_box_candidate EXIT
        trap 'exit 130' INT TERM
        trap 'exit 129' HUP
        cp "$1" "$sb_stage/sing-box" || exit 1
        chmod 0755 "$sb_stage/sing-box" || exit 1
        if ! "$sb_stage/sing-box" version >/dev/null 2>&1; then
            if ! make_entware_sing_box_wrapper "$sb_stage/sing-box"; then
                say "Новый sing-box не запускается с ABI установленного Entware. Прежние файлы не изменены." "The new sing-box cannot run with this Entware ABI. Previous files were not changed." >&2
                exit 1
            fi
            sb_wrapped=1
        fi
        for sb_name in sing-box sing-box.real; do
            [ ! -d "/opt/bin/$sb_name" ] || exit 1
            if [ -e "/opt/bin/$sb_name" ] || [ -L "/opt/bin/$sb_name" ]; then
                cp -a "/opt/bin/$sb_name" "$sb_stage/old-$sb_name" || exit 1
            fi
        done
        sb_publish_started=1
        if [ -f "$sb_stage/sing-box.real" ]; then
            mv -f "$sb_stage/sing-box.real" /opt/bin/sing-box.real || exit 1
        fi
        mv -f "$sb_stage/sing-box" /opt/bin/sing-box || exit 1
        /opt/bin/sing-box version >/dev/null 2>&1 || exit 1
        # A directly executable replacement no longer needs the old wrapper's
        # payload. Remove it only after the new entry point works.
        if [ "$sb_wrapped" = 0 ]; then
            rm -f /opt/bin/sing-box.real || exit 1
        fi
        sb_committed=1
    )
}

install_sing_box() {
    requested_version=$1
    [ "$requested_version" = "$SING_BOX_PINNED_VERSION" ] ||
        die "разрешена только зафиксированная версия sing-box $SING_BOX_PINNED_VERSION" "only the pinned sing-box version $SING_BOX_PINNED_VERSION is supported"
    case "$KEEN_ARCH" in
        aarch64) sing_arch="arm64" ;;
        armv7) sing_arch="armv7" ;;
        mipsel) sing_arch="mipsle" ;;
        mips) sing_arch="mips" ;;
        x64) sing_arch="amd64" ;;
        *) die "для архитектуры $KEEN_ARCH не задан официальный архив sing-box" "there is no configured official sing-box archive for $KEEN_ARCH" ;;
    esac

    release_json="$TMP_DIR/sing-box-release-${requested_version}.json"
    fetch "$GITHUB_API/SagerNet/sing-box/releases/tags/v${requested_version}" "$release_json"
    archive_url=$(github_asset_urls "$release_json" | grep -E "/sing-box-${requested_version}-linux-${sing_arch}\\.tar\\.gz$" | head -n 1 || true)
    [ -n "$archive_url" ] || die "в официальном выпуске sing-box ${requested_version} нет архива linux-$sing_arch" "the official sing-box ${requested_version} release has no linux-$sing_arch archive"
    archive="$TMP_DIR/$(basename "$archive_url")"
    fetch "$archive_url" "$archive"

    checksums_url=$(github_asset_urls "$release_json" | grep -E '/sing-box-[^/]+-checksums\\.txt$' | head -n 1 || true)
    if [ -n "$checksums_url" ]; then
        fetch "$checksums_url" "$TMP_DIR/sing-box-checksums.txt"
        expected=$(awk -v name="$(basename "$archive")" '$2 == name || $2 == "*" name { print $1; exit }' "$TMP_DIR/sing-box-checksums.txt")
        [ -n "$expected" ] || die "архив sing-box отсутствует в файле контрольных сумм" "the sing-box archive is missing from the checksums file"
        actual=$(sha256sum "$archive" | awk '{print $1}')
        [ "$actual" = "$expected" ] || die "контрольная сумма sing-box не совпадает" "the sing-box checksum does not match"
    fi

    mkdir -p "$TMP_DIR/sing-box" /opt/bin /opt/etc/keen-pbr
    tar -xzf "$archive" -C "$TMP_DIR/sing-box"
    binary=$(find "$TMP_DIR/sing-box" -type f -name sing-box | head -n 1)
    [ -n "$binary" ] || die "исполняемый файл sing-box не найден в архиве" "the sing-box executable was not found in the archive"
    publish_sing_box_candidate "$binary" ||
        die "Не удалось установить новый sing-box. Проверьте сообщение об ошибке выше и повторите установку." "Could not install the new sing-box. Check the error above and retry."
    printf '%s\n' /opt/bin/sing-box > /opt/etc/keen-pbr/sing-box-managed.path
    SING_BOX_PATH=/opt/bin/sing-box
}

choose_sing_box() {
    existing=$(find_existing_sing_box || true)
    if [ -n "$existing" ]; then
        current=$(sing_box_version "$existing")
        say "Найден sing-box: $existing (версия ${current:-не определена})" "Found sing-box: $existing (version ${current:-unknown})"
        say "  1) Использовать найденный файл (рекомендуется, если он уже проверен)" "  1) Use the existing binary (recommended if already tested)"
        say "  2) Установить зафиксированную версию $SING_BOX_PINNED_VERSION в /opt/bin" "  2) Install pinned version $SING_BOX_PINNED_VERSION into /opt/bin"
        say "  3) Указать другой существующий путь" "  3) Choose another existing path"
        say "  4) Продолжить без sing-box (только нативные интерфейсы)" "  4) Continue without sing-box (native interfaces only)"
        choice=$(ask "Выберите [1-4] (по умолчанию 1):" "1" "Choose [1-4] (default 1):")
    else
        say "sing-box не найден в стандартных каталогах." "sing-box was not found in the standard directories."
        say "  1) Установить зафиксированную версию $SING_BOX_PINNED_VERSION в /opt/bin (рекомендуется)" "  1) Install pinned version $SING_BOX_PINNED_VERSION into /opt/bin (recommended)"
        say "  2) Указать другой существующий путь" "  2) Choose another existing path"
        say "  3) Продолжить без sing-box (только нативные интерфейсы)" "  3) Continue without sing-box (native interfaces only)"
        choice=$(ask "Выберите [1-3] (по умолчанию 1):" "1" "Choose [1-3] (default 1):")
        case "$choice" in 1) choice=2 ;; 2) choice=3 ;; 3) choice=4 ;; *) die "неверный выбор" "invalid choice" ;; esac
    fi

    case "$choice" in
        1) SING_BOX_PATH="$existing" ;;
        2) install_sing_box "$SING_BOX_PINNED_VERSION" ;;
        3)
            SING_BOX_PATH=$(ask "Абсолютный путь к sing-box:" "" "Absolute path to sing-box:")
            [ -x "$SING_BOX_PATH" ] || die "файл не является исполняемым: $SING_BOX_PATH" "the file is not executable: $SING_BOX_PATH"
            "$SING_BOX_PATH" version >/dev/null || die "выбранный sing-box не запускается" "the selected sing-box does not start"
            ;;
        4) SING_BOX_PATH="" ;;
        *) die "неверный выбор" "invalid choice" ;;
    esac
}

set_sing_box_path() {
    [ -n "$SING_BOX_PATH" ] || return 0
    [ -f "$TRANSPORT_CONFIG" ] || die "конфигурация транспортов не установлена" "transport configuration is not installed"
    escaped=$(printf '%s' "$SING_BOX_PATH" | sed 's/[\\&|]/\\&/g')
    sed -i "s|\"sing_box_binary\"[[:space:]]*:[[:space:]]*\"[^\"]*\"|\"sing_box_binary\": \"$escaped\"|" "$TRANSPORT_CONFIG"
    chmod 0600 "$TRANSPORT_CONFIG"
    /opt/etc/init.d/S79transport-manager restart
}

configure_web_auth() {
    local auth_file=/opt/etc/keen-pbr/auth.json
    local choice username password confirmation escaped_username escaped_password
    local candidate backup published
    [ -d /opt/etc/keen-pbr ] && [ -x /opt/etc/init.d/S80keen-pbr ] ||
        die "keen-pbr-sb ещё не установлен. Сначала запустите установщик без --configure-auth." "keen-pbr-sb is not installed yet. Run the installer without --configure-auth first."

    say "Для входа в веб-интерфейс нужен пароль. Выберите способ входа:" "The web interface requires a password. Choose a sign-in method:"
    say "  1) Логин и пароль администратора Keenetic/Netcraze (рекомендуется)" "  1) Keenetic/Netcraze administrator username and password (recommended)"
    say "  2) Отдельный логин и пароль только для keen-pbr-sb" "  2) A separate username and password for keen-pbr-sb only"
    while :; do
        choice=$(ask "Выберите [1-2] (по умолчанию 1):" "1" "Choose [1-2] (default 1):")
        case "$choice" in 1|2) break ;; esac
        say "Введите 1 или 2. Варианта без пароля нет." "Enter 1 or 2. Password-free access is not available."
    done

    candidate="$TMP_DIR/auth.json"
    if [ "$choice" = 1 ]; then
        # The router validates its own credentials. Do not copy its password.
        printf '%s\n' '{"enabled":true,"provider":"keenetic","keenetic_endpoint_mode":"auto","session_ttl_seconds":604800}' > "$candidate"
    else
        say "Этот пароль действует только в keen-pbr-sb и не меняет пароль роутера или SSH." "This password is for keen-pbr-sb only. It does not change your router or SSH password."
        while :; do
            username=$(ask "Логин веб-интерфейса (по умолчанию admin):" "admin" "Web interface username (default admin):")
            if [ -n "$username" ] && ! printf '%s' "$username" | LC_ALL=C grep -q '[[:cntrl:]]'; then
                break
            fi
            say "Введите непустой логин без табуляции и управляющих символов." "Enter a non-empty username without tabs or control characters."
        done
        while :; do
            password=$(ask_secret "Пароль веб-интерфейса:" "Web interface password:") ||
                die "ввод прерван; настройки входа не изменены." "input was interrupted; sign-in settings were not changed."
            if [ -z "$password" ]; then
                say "Пароль не может быть пустым. Введите его ещё раз." "The password cannot be empty. Enter it again."
                continue
            fi
            if printf '%s' "$password" | LC_ALL=C grep -q '[[:cntrl:]]'; then
                say "Пароль содержит табуляцию или управляющий символ. Введите его ещё раз." "The password contains a tab or control character. Enter it again."
                continue
            fi
            confirmation=$(ask_secret "Повторите пароль:" "Repeat password:") ||
                die "ввод прерван; настройки входа не изменены." "input was interrupted; sign-in settings were not changed."
            [ "$password" = "$confirmation" ] && break
            say "Пароли не совпали. Введите пароль ещё раз." "Passwords do not match. Enter the password again."
        done
        escaped_username=$(printf '%s' "$username" | sed 's/[\\"]/\\&/g')
        escaped_password=$(printf '%s' "$password" | sed 's/[\\"]/\\&/g')
        printf '{"enabled":true,"provider":"local","username":"%s","password":"%s","session_ttl_seconds":604800}\n' \
            "$escaped_username" "$escaped_password" > "$candidate"
        unset password confirmation escaped_password
    fi
    chmod 0600 "$candidate"
    if [ -f "$auth_file" ]; then
        backup=$(mktemp "$auth_file.before-installer.XXXXXX") || die "не удалось сохранить прежние настройки входа." "could not back up the previous sign-in settings."
        cp "$auth_file" "$backup" && chmod 0600 "$backup" || die "не удалось сохранить прежние настройки входа." "could not back up the previous sign-in settings."
        say "Прежние настройки входа сохранены в $backup" "Previous sign-in settings were backed up to $backup"
    fi
    # Publish on the destination filesystem, only after all input is complete.
    published=$(mktemp "$auth_file.new.XXXXXX") || die "не удалось сохранить настройки входа." "could not save sign-in settings."
    if ! { cp "$candidate" "$published" && chmod 0600 "$published" && mv -f "$published" "$auth_file"; }; then
        rm -f "$published"
        die "не удалось сохранить настройки входа; прежний файл не заменён." "could not save sign-in settings; the previous file was not replaced."
    fi
    say "Настройки входа сохранены. Перезапускаю keen-pbr-sb, чтобы применить их; панель временно отключится." "Sign-in settings saved. Restarting keen-pbr-sb to apply them; the panel will briefly disconnect."
    /opt/etc/init.d/S80keen-pbr restart ||
        die "настройки входа сохранены, но служба не запустилась. Проверьте /opt/var/log/keen-pbr.log." "sign-in settings were saved, but the service did not start. Check /opt/var/log/keen-pbr.log."
    if [ ! -x "$RESCUE_HELPER" ]; then
        RESCUE_HELPER=/opt/usr/lib/keen-pbr/rescue-update.sh
    fi
    [ -x "$RESCUE_HELPER" ] && verify_installed_runtime 3 ||
        die "настройки входа сохранены, но готовность панели пока не подтверждена. Проверьте /opt/var/log/keen-pbr.log; пакет переустанавливать не нужно." "sign-in settings were saved, but the panel is not confirmed ready. Check /opt/var/log/keen-pbr.log; you do not need to reinstall the package."
    if [ "$choice" = 1 ]; then
        say "Вход настроен: используйте в панели логин и пароль администратора роутера, не пароль root Entware." "Sign-in is configured: use your router administrator username and password, not the Entware root password."
    else
        say "Вход настроен: используйте в панели указанный отдельный логин и пароль." "Sign-in is configured: use the separate username and password you just entered."
    fi
}

read_dns_override_state() {
    # Read the running setting, not startup-config: an unsaved user setting is
    # still the state this optional setup must restore. Never print the full
    # running configuration, including on a failed read.
    run_ndmc "show running-config" 2>/dev/null || return 1
    [ -n "$ndmc_output" ] || return 1
    printf '%s\n' "$ndmc_output" | awk '
        /^[[:space:]]*opkg[[:space:]]+dns-override[[:space:]]*$/ { enabled=1 }
        /^[[:space:]]*no[[:space:]]+opkg[[:space:]]+dns-override[[:space:]]*$/ { enabled=0 }
        END { print enabled ? "Y" : "N" }
    '
}

restore_dns_setup() {
    local previous_override="$1" was_running="$2" config="$3" backup="$4"
    local had_config="$5" restart_attempted="$6" restored=Y
    if [ "$had_config" = Y ]; then
        cp -p "$backup" "$config" || restored=N
    else
        rm -f "$config" || restored=N
    fi
    # If restart was never attempted the old process is still untouched.
    # Otherwise stop the candidate before returning port 53 to Keenetic.
    if [ "$restart_attempted" = Y ]; then
        /opt/etc/init.d/S56dnsmasq stop >/dev/null 2>&1 || restored=N
    fi
    if [ "$previous_override" = Y ]; then
        run_ndmc "opkg dns-override" || restored=N
    else
        run_ndmc "no opkg dns-override" || restored=N
    fi
    if ! run_ndmc "system configuration save"; then
        say "ПРЕДУПРЕЖДЕНИЕ: не удалось сохранить восстановленную настройку DNS в Keenetic." "WARNING: could not save the restored DNS setting in Keenetic." >&2
        restored=N
    fi
    if [ "$restart_attempted" = Y ] && [ "$was_running" = Y ]; then
        /opt/etc/init.d/S56dnsmasq start >/dev/null 2>&1 || restored=N
    fi
    [ "$restored" = Y ]
}

ask_dns_setup() {
    say "Если выбрать N, сервис не будет работать полноценно без ручной настройки DNS: правила по доменам требуют запросов через dnsmasq. Выберите Y для автоматической настройки или N, если уже настроили DNS вручную." \
        "If you choose N, the service will not work fully unless DNS is configured manually: domain-based rules need queries through dnsmasq. Choose Y for automatic setup, or N if you have already configured DNS manually." >&2
    ask "Включить Keenetic DNS Override и настроить dnsmasq Entware? [Y/n]:" "Y" \
        "Enable Keenetic DNS Override and configure Entware dnsmasq? [Y/n]:"
}

configure_dns() {
    answer=${DNS_SETUP_CHOICE:-}
    if [ -z "$answer" ]; then
        answer=$(ask_dns_setup)
    fi
    case "$answer" in
        n|N|no|NO) return 0 ;;
    esac

    previous_override=$(read_dns_override_state) ||
        die "не удалось прочитать текущее состояние DNS Override; настройки DNS не изменены" "could not read the current DNS Override state; DNS settings were not changed"
    dns_was_running=N
    if pidof dnsmasq >/dev/null 2>&1; then dns_was_running=Y; fi
    template=${1:-/opt/usr/lib/keen-pbr/dnsmasq.conf.template}
    config=/opt/etc/dnsmasq.conf
    [ -f "$template" ] || die "шаблон dnsmasq отсутствует" "the dnsmasq template is missing"
    /opt/sbin/dnsmasq --test --conf-file="$template" >/dev/null 2>&1 || die "сгенерированная конфигурация dnsmasq некорректна" "the generated dnsmasq configuration is invalid"
    # Keep an operator's symlink itself unchanged. Publish beside its resolved
    # target so rename stays on the same filesystem even for a custom target.
    if [ -L "$config" ]; then
        config=$(readlink -f "$config") && [ -n "$config" ] ||
            die "не удалось определить файл конфигурации dnsmasq; настройки DNS не изменены" "could not identify the dnsmasq configuration file; DNS settings were not changed"
    fi
    [ ! -e "$config" ] || [ -f "$config" ] ||
        die "конфигурация dnsmasq не является обычным файлом; настройки DNS не изменены" "the dnsmasq configuration is not a regular file; DNS settings were not changed"
    backup="$config.backup-mykeenpbr-$(date +%Y%m%d%H%M%S)"
    had_config=N
    if [ -f "$config" ]; then
        cp -p "$config" "$backup" ||
            die "не удалось сохранить прежнюю конфигурацию dnsmasq; настройки DNS не изменены" "could not back up the previous dnsmasq configuration; DNS settings were not changed"
        had_config=Y
    fi

    # Never truncate the working file before the new bytes and permissions are
    # ready. ENOSPC, chmod and rename failures leave the old DNS state intact.
    candidate=$(mktemp "$config.new-mykeenpbr.XXXXXX") ||
        die "не удалось подготовить конфигурацию dnsmasq; настройки DNS не изменены" "could not prepare dnsmasq configuration; DNS settings were not changed"
    if ! cp "$template" "$candidate" ||
       ! chmod 0600 "$candidate" ||
       ! mv -f "$candidate" "$config"; then
        rm -f "$candidate" || true
        die "не удалось записать конфигурацию dnsmasq; настройки DNS не изменены" "could not write dnsmasq configuration; DNS settings were not changed"
    fi
    if [ "${DNS_BOOTSTRAP:-0}" = 1 ]; then
        INSTALL_DNS_OVERRIDE=$previous_override
        INSTALL_DNS_RUNNING=$dns_was_running
        INSTALL_DNS_CONFIG=$config
        INSTALL_DNS_BACKUP=$backup
        INSTALL_DNS_HAD_CONFIG=$had_config
        INSTALL_DNS_RESTARTED=N
        DNS_INSTALL_ROLLBACK=1
    fi
    if ! run_ndmc "opkg dns-override" ||
       ! run_ndmc "system configuration save"; then
        if restore_dns_setup "$previous_override" "$dns_was_running" \
            "$config" "$backup" "$had_config" N; then
            DNS_INSTALL_ROLLBACK=0
        else
            say "ПРЕДУПРЕЖДЕНИЕ: восстановление прежнего DNS завершено не полностью; проверьте DNS в Keenetic." "WARNING: previous DNS settings were not fully restored; check DNS in Keenetic." >&2
        fi
        die "не удалось включить opkg dns-override" "could not enable opkg dns-override"
    fi
    INSTALL_DNS_RESTARTED=Y
    if ! /opt/etc/init.d/S56dnsmasq restart; then
        if restore_dns_setup "$previous_override" "$dns_was_running" \
            "$config" "$backup" "$had_config" Y; then
            DNS_INSTALL_ROLLBACK=0
        else
            say "ПРЕДУПРЕЖДЕНИЕ: восстановление прежнего DNS завершено не полностью; проверьте DNS в Keenetic." "WARNING: previous DNS settings were not fully restored; check DNS in Keenetic." >&2
        fi
        die "dnsmasq не запустился; выполнен возврат к прежним настройкам DNS" "dnsmasq did not start; previous DNS settings were restored"
    fi
    if ! nslookup google.com 127.0.0.1 >/dev/null 2>&1; then
        say "ПРЕДУПРЕЖДЕНИЕ: dnsmasq запущен, но быстрая проверка внешнего DNS не прошла." "WARNING: dnsmasq is running, but the quick external DNS check did not pass."
        say "Установка продолжится; проверьте состояние DNS и диагностику в веб-интерфейсе." "Installation will continue; check DNS status and diagnostics in the web interface."
    fi
}

choose_optional_setup() {
    DNS_SETUP_CHOICE=$(ask_dns_setup)
    if /opt/bin/opkg status nfqws2-keenetic 2>/dev/null | grep -q '^Status:.* installed'; then
        NFQWS_SETUP_CHOICE=$(ask "nfqws2 уже установлен. Обновить его из официального репозитория? [y/N]:" "N" "nfqws2 is already installed. Update it from the official repository? [y/N]:")
    else
        NFQWS_SETUP_CHOICE=$(ask "Установить nfqws2 из официального репозитория nfqws/nfqws2-keenetic? [y/N]:" "N" "Install nfqws2 from the official nfqws/nfqws2-keenetic repository? [y/N]:")
    fi
}

prepare_first_install_dns() {
    # A working/fully configured package keeps its existing DNS until the
    # optional setup at the end. --update never enters this first-run path.
    if [ "${RESUME_FIRST_INSTALL:-0}" != 1 ] &&
       /opt/bin/opkg status keen-pbr 2>/dev/null | grep -q '^Status:.* installed'; then
        return 0
    fi
    case "$DNS_SETUP_CHOICE" in
        n|N|no|NO)
            # Respect manual DNS setups, but explain an unmet prerequisite
            # before opkg leaves an unpacked package with a failed postinst.
            if [ -x /opt/sbin/dnsmasq ] && pidof dnsmasq >/dev/null 2>&1; then
                return 0
            fi
            die "Для первого запуска нужен работающий dnsmasq. Повторите установку и разрешите настройку DNS Override либо сначала настройте dnsmasq вручную. Пакет keen-pbr ещё не устанавливался." "The first start requires a working dnsmasq. Rerun the installer and allow DNS Override setup, or configure dnsmasq manually first. The keen-pbr package has not been installed."
            ;;
    esac

    say "Подготавливаю DNS перед первым запуском keen-pbr-sb..." "Preparing DNS before the first start of keen-pbr-sb..."
    if [ ! -x /opt/sbin/dnsmasq ] || [ ! -x /opt/etc/init.d/S56dnsmasq ]; then
        /opt/bin/opkg install dnsmasq || die "не удалось установить dnsmasq; DNS Keenetic не изменён" "could not install dnsmasq; Keenetic DNS was not changed"
    fi
    [ -x /opt/sbin/dnsmasq ] && [ -x /opt/etc/init.d/S56dnsmasq ] ||
        die "dnsmasq не установлен; DNS Keenetic не изменён" "dnsmasq is not installed; Keenetic DNS was not changed"

    # Use the already authenticated IPK, not another download or an installed
    # helper which does not exist on a clean router yet. The package's existing
    # standalone block is reattached by its unchanged postinst after unpacking.
    local first_template="$TMP_DIR/first-dnsmasq.template"
    local first_fallback="$TMP_DIR/first-dnsmasq.fallback"
    local first_config="$TMP_DIR/first-dnsmasq.conf"
    tar -xzOf "$TMP_DIR/data.tar.gz" ./opt/usr/lib/keen-pbr/dnsmasq.conf.template > "$first_template" &&
        tar -xzOf "$TMP_DIR/data.tar.gz" ./opt/etc/keen-pbr/dnsmasq-fallback.conf > "$first_fallback" ||
        die "в проверенном IPK отсутствуют файлы начальной настройки DNS" "the verified IPK is missing initial DNS setup files"
    # An existing fallback may contain deliberate operator settings. Preserve
    # its directives instead of substituting the packaged bootstrap resolver.
    if [ -f /opt/etc/keen-pbr/dnsmasq-fallback.conf ]; then
        cp /opt/etc/keen-pbr/dnsmasq-fallback.conf "$first_fallback" ||
            die "не удалось прочитать существующую резервную конфигурацию DNS" "could not read the existing DNS fallback configuration"
    fi
    awk -v fallback="$first_fallback" '
        $0 == "conf-script=/opt/usr/lib/keen-pbr/dnsmasq.sh dnsmasq-config-entry" {
            print "# BEGIN keen-pbr standalone DNS fallback v1"
            while ((getline line < fallback) > 0) print line
            close(fallback)
            print "# END keen-pbr standalone DNS fallback v1"
            found++
            next
        }
        { print }
        END { if (found != 1) exit 1 }
    ' "$first_template" > "$first_config" ||
        die "не удалось подготовить начальную конфигурацию DNS" "could not prepare the initial DNS configuration"
    DNS_BOOTSTRAP=1
    configure_dns "$first_config"
}

remember_initial_nfqws_config() {
    # Only the installer knows that no operator configuration preceded opkg.
    # Snapshot the actual postinst result (including detected WAN and IPv6),
    # not our historical built-in "default", which may use other arguments.
    local source=/opt/etc/nfqws2/nfqws2.conf
    local directory=/opt/etc/keen-pbr/nfqws-strategies
    local base="default ($(date +%Y.%m.%d))"
    local index=1
    local destination
    [ -f "$source" ] || return 1
    mkdir -p "$directory" || return 1
    while [ "$index" -le 100 ]; do
        destination="$directory/$base.conf"
        [ "$index" = 1 ] || destination="$directory/$base $index.conf"
        if [ -e "$destination" ] || [ -L "$destination" ]; then
            cmp -s "$source" "$destination" && return 0
        else
            # noclobber also preserves a strategy saved concurrently in the UI.
            (set -C; cat "$source" > "$destination") && return 0
        fi
        index=$((index + 1))
    done
    return 1
}

configure_nfqws2() {
    answer=${NFQWS_SETUP_CHOICE:-N}
    case "$answer" in y|Y|yes|YES|д|Д|да|ДА) ;; *) return 0 ;; esac

    say "Подготавливаю HTTPS и официальный репозиторий nfqws2..." "Preparing HTTPS and the official nfqws2 repository..."
    # Старый wget из Entware понимает только HTTP/FTP. Сначала обновляем
    # обычные feeds и заменяем его на SSL-вариант, и только после этого
    # добавляем HTTPS-feed nfqws2. Временное перемещение feed чинит повторный запуск
    # после ранее прерванной установки.
    mkdir -p /opt/etc/opkg
    if [ -f /opt/etc/opkg/nfqws2-keenetic.conf ] ||
       [ -L /opt/etc/opkg/nfqws2-keenetic.conf ]; then
        NFQWS_SAVED_FEED="$TMP_DIR/nfqws2-keenetic.conf"
        mv /opt/etc/opkg/nfqws2-keenetic.conf "$NFQWS_SAVED_FEED"
    else
        rm -f /opt/etc/opkg/nfqws2-keenetic.conf
    fi
    /opt/bin/opkg update || die "не удалось обновить список пакетов Entware" "could not update the Entware package lists"
    /opt/bin/opkg install ca-certificates wget-ssl || die "не удалось установить HTTPS-зависимости nfqws2" "could not install HTTPS dependencies for nfqws2"
    /opt/bin/opkg remove wget-nossl >/dev/null 2>&1 || true
    printf '%s\n' 'src/gz nfqws2-keenetic https://nfqws.github.io/nfqws2-keenetic/all' > /opt/etc/opkg/nfqws2-keenetic.conf
    NFQWS_SAVED_FEED=
    /opt/bin/opkg update || die "не удалось загрузить официальный репозиторий nfqws2" "could not load the official nfqws2 repository"
    say "Устанавливаю пакет nfqws2..." "Installing the nfqws2 package..."
    local capture_default=0
    if [ ! -e /opt/etc/nfqws2/nfqws2.conf ] &&
       [ ! -L /opt/etc/nfqws2/nfqws2.conf ]; then
        capture_default=1
    fi
    if /opt/bin/opkg status nfqws2-keenetic 2>/dev/null | grep -q '^Status:.* installed'; then
        /opt/bin/opkg upgrade nfqws2-keenetic || die "не удалось обновить nfqws2" "could not update nfqws2"
    else
        /opt/bin/opkg install nfqws2-keenetic || die "не удалось установить nfqws2" "could not install nfqws2"
    fi
    if [ "$capture_default" = 1 ]; then
        remember_initial_nfqws_config ||
            say "nfqws2 установлен, но стандартную конфигурацию не удалось сохранить в списке стратегий. Активный конфиг не изменён." "nfqws2 is installed, but its standard configuration could not be saved in the strategy list. The active configuration is unchanged." >&2
    fi
    say "nfqws2 установлен. Управление доступно в разделе «nfqws2» веб-интерфейса keen-pbr-sb." "nfqws2 is installed. Manage it in the nfqws2 section of the keen-pbr-sb web interface."
}

prepare_first_install_retry() {
    RESUME_FIRST_INSTALL=0
    if [ ! -e "$RESCUE_DIR/pending" ] && [ ! -L "$RESCUE_DIR/pending" ] &&
       [ ! -e "$RESCUE_DIR/UNKNOWN" ] && [ ! -L "$RESCUE_DIR/UNKNOWN" ]; then
        return 0
    fi
    # No working baseline exists after a failed first install. A newly signed
    # package must be able to repair that install, not be rejected merely for
    # differing from the package which failed. Keep its journal/config snapshot;
    # never apply this path to an interrupted upgrade with a working baseline.
    local item
    for item in current.ipk current.ipk.sha256 previous.ipk previous.ipk.sha256 \
        pending-baseline.ipk pending-baseline.ipk.sha256; do
        [ ! -e "$RESCUE_DIR/$item" ] && [ ! -L "$RESCUE_DIR/$item" ] ||
            die "Незавершённое обновление имеет предыдущий пакет; требуется его восстановление. Первая установка не начата." "The interrupted update has a previous package to restore. First installation has not started."
    done
    [ -f "$RESCUE_DIR/pending" ] && [ ! -L "$RESCUE_DIR/pending" ] &&
        [ "$(cat "$RESCUE_DIR/pending")" = candidate-staged ] &&
        [ -f "$RESCUE_DIR/candidate.ipk" ] && [ ! -L "$RESCUE_DIR/candidate.ipk" ] ||
        die "Незавершённая установка находится на другом этапе или её пакет отсутствует. Сохранённые файлы не изменены." "The interrupted installation is at a different stage or its package is missing. Saved files were not changed."
    if [ -e "$RESCUE_DIR/UNKNOWN" ] || [ -L "$RESCUE_DIR/UNKNOWN" ]; then
        [ -f "$RESCUE_DIR/UNKNOWN" ] && [ ! -L "$RESCUE_DIR/UNKNOWN" ] &&
            [ "$(cat "$RESCUE_DIR/UNKNOWN")" = 'candidate rollback has no verified baseline' ] ||
            die "Причина незавершённой установки отличается от сбоя первого запуска. Сохранённые файлы не изменены." "The interrupted installation was not caused by first-start failure. Saved files were not changed."
    fi
    local sidecar="$RESCUE_DIR/candidate.ipk.sha256"
    [ ! -L "$sidecar" ] && { [ ! -e "$sidecar" ] || [ -f "$sidecar" ]; } ||
        die "Файл контрольной суммы незавершённой установки повреждён. Сохранённый пакет не изменён." "The interrupted installation checksum path is invalid. The saved package was not changed."
    # PACKAGE_FILE has already passed download_package's signature, target and
    # digest verification. Also repair a partial IPK/sidecar publication after
    # interruption: matching the freshly verified download is the authority,
    # not the old sidecar. Do not clear PENDING or UNKNOWN before runtime checks.
    [ -f "$PACKAGE_FILE" ] && [ -s "$PACKAGE_FILE" ] && [ ! -L "$PACKAGE_FILE" ] ||
        die "Загруженный пакет недоступен. Сохранённая установка не изменена." "The downloaded package is unavailable. The saved installation was not changed."
    local digest
    digest=$(sha256sum "$PACKAGE_FILE") || return 1
    digest=${digest%%[[:space:]]*}
    [ "${#digest}" -eq 64 ] || return 1
    case "$digest" in *[!0-9a-f]*) return 1 ;; esac
    local same_package=0
    cmp -s "$PACKAGE_FILE" "$RESCUE_DIR/candidate.ipk" && same_package=1
    if [ "$same_package" != 1 ] || [ "$(cat "$sidecar" 2>/dev/null || true)" != "$digest" ] ||
       [ "$(wc -l < "$sidecar" 2>/dev/null || true)" -ne 1 ]; then
        local retry_dir
        retry_dir=$(mktemp -d "$RESCUE_DIR/.first-install-retry.XXXXXX") || return 1
        chmod 0700 "$retry_dir" || return 1
        if ! cp "$PACKAGE_FILE" "$retry_dir/candidate.ipk" ||
           ! cmp -s "$PACKAGE_FILE" "$retry_dir/candidate.ipk" ||
           ! printf '%s\n' "$digest" > "$retry_dir/candidate.ipk.sha256" ||
           ! chmod 0600 "$retry_dir/candidate.ipk" "$retry_dir/candidate.ipk.sha256"; then
            rm -f "$retry_dir/candidate.ipk" "$retry_dir/candidate.ipk.sha256"
            rmdir "$retry_dir" 2>/dev/null || true
            die "Не удалось сохранить новый пакет для повторной установки. Прежний пакет и настройки не изменены; проверьте свободное место Entware." "Could not save the new package for retry. The previous package and settings were not changed; check free space in Entware."
        fi
        if [ "$same_package" != 1 ]; then
            local archive_dir
            archive_dir=$(mktemp -d "$RESCUE_DIR/failed-first-install.XXXXXX") || return 1
            chmod 0700 "$archive_dir" &&
                cp -p "$RESCUE_DIR/candidate.ipk" "$RESCUE_DIR/pending" "$archive_dir/" || return 1
            [ ! -f "$sidecar" ] || cp -p "$sidecar" "$archive_dir/" || return 1
            [ ! -f "$RESCUE_DIR/UNKNOWN" ] || cp -p "$RESCUE_DIR/UNKNOWN" "$archive_dir/" || return 1
            sync || return 1
            say "Прежний пакет неудачной установки сохранён: $archive_dir" "The previous failed-install package is retained at: $archive_dir"
        fi
        # A crash between these renames leaves PENDING intact. Repeating this
        # same signed download repairs the sidecar and continues normally.
        mv -f "$retry_dir/candidate.ipk" "$RESCUE_DIR/candidate.ipk" &&
            mv -f "$retry_dir/candidate.ipk.sha256" "$sidecar" && sync ||
            die "Подготовка повторной установки прервалась. Повторите ту же команду; настройки и прежний пакет сохранены." "Retry preparation was interrupted. Repeat the same command; settings and the previous package are retained."
        rmdir "$retry_dir" 2>/dev/null || true
    fi
    RESUME_FIRST_INSTALL=1
    say "Завершаю первую установку выбранным подписанным IPK; настройки и резервная копия сохраняются." "Completing first installation with the selected signed IPK; settings and backup will be retained."
}

verify_installed_runtime() {
    local windows="$1"
    local attempt=1
    local result=1
    say "Ожидаю готовности служб и веб-интерфейса..." "Waiting for the services and web interface to become ready..."
    while [ "$attempt" -le "$windows" ]; do
        if "$RESCUE_HELPER" verify; then
            return 0
        else
            result=$?
        fi
        # Retry a completed readiness timeout, not a lock/metadata error.
        # The helper already reports those errors itself.
        case "$result" in 1) ;; *) return "$result" ;; esac
        [ "$attempt" -lt "$windows" ] || break
        attempt=$((attempt + 1))
        say "Первый запуск ещё не подтверждён. Продолжаю ожидание ($attempt/$windows), службы не перезапускаю." "First start is not yet confirmed. Still waiting ($attempt/$windows), without restarting services."
    done
    say "Готовность служб или веб-интерфейса не подтверждена за отведённое время." "The services or web interface did not become ready within the allotted time."
    /opt/etc/init.d/S80keen-pbr check 2>&1 || true
    /opt/etc/init.d/S79transport-manager check 2>&1 || true
    say "Причина запуска записана в /opt/var/log/keen-pbr.log." "Check the startup diagnostics in /opt/var/log/keen-pbr.log."
    return "$result"
}

install_package_transactionally() {
    [ ! -L "$RESCUE_DIR" ] &&
        { [ ! -e "$RESCUE_DIR" ] || [ -d "$RESCUE_DIR" ]; } ||
        die "каталог rescue имеет небезопасный тип" "the recovery path is not a regular directory"
    mkdir -p "$RESCUE_DIR"
    chmod 0700 "$RESCUE_DIR" ||
        die "не удалось защитить каталог rescue" "could not set permissions on the recovery directory"
    [ -x "$RESCUE_HELPER" ] ||
        die "rescue helper не установлен" "the recovery helper is not installed"
    if [ "${RESUME_FIRST_INSTALL:-0}" != 1 ]; then
        "$RESCUE_HELPER" stage "$PACKAGE_FILE"
    fi

    local recovery_capability=
    local verification_windows=1
    if [ "${RESUME_FIRST_INSTALL:-0}" = 1 ]; then
        recovery_capability=recover-pending-v1
    fi
    # Published helpers use one ~30s readiness window (longer for HTTP
    # timeouts). A clean Keenetic boot can legitimately publish its API only
    # after the daemon's 30s route-observation retry. Give first installation
    # up to three bounded windows, retaining the same three stable successful
    # observations in each. Never restart a service between observations.
    # Capture this BEFORE opkg marks a successful postinst as installed.
    if [ "$UPDATE_ONLY" = 0 ] &&
       { [ "${RESUME_FIRST_INSTALL:-0}" = 1 ] ||
         ! /opt/bin/opkg status keen-pbr 2>/dev/null | grep -q '^Status:.* installed'; }; then
        verification_windows=3
    fi
    FIRST_PACKAGE_STARTED=1

    if PKG_UPGRADE=1 \
           KEEN_PBR_RESCUE_TRANSACTION=1 \
           KEEN_PBR_PACKAGE_UNKNOWN_RECOVERY="$recovery_capability" \
           KEEN_PBR_REPLACE_DNSMASQ_DEFAULTS=N \
           /opt/bin/opkg --force-reinstall install "$PACKAGE_FILE" &&
       [ -x "$RESCUE_HELPER" ] &&
       verify_installed_runtime "$verification_windows"; then
        # The no-baseline marker is cleared only after the selected signed package
        # has actually started and passed the existing runtime verification.
        if [ "${RESUME_FIRST_INSTALL:-0}" = 1 ]; then
            rm -f "$RESCUE_DIR/UNKNOWN" && sync || return 1
        fi
        if "$RESCUE_HELPER" promote; then
            DNS_INSTALL_ROLLBACK=0
            return 0
        fi
        say "ОШИБКА: пакет работает, но rescue-снимок не удалось зафиксировать." "ERROR: the package is running, but its recovery snapshot could not be finalized."
    fi

    say "ОШИБКА: новый пакет не прошёл проверку после установки." "ERROR: the new package did not pass the post-installation check."
    if [ ! -e "$RESCUE_DIR/pending-baseline.ipk" ] &&
       [ ! -L "$RESCUE_DIR/pending-baseline.ipk" ]; then
        say "Первая установка не завершена. Предыдущего IPK ещё нет; сохранённую установку можно продолжить повторным запуском этой команды." "First installation is incomplete. No previous IPK exists yet; rerun this command to resume the saved installation."
    elif [ -x "$RESCUE_HELPER" ] &&
       "$RESCUE_HELPER" rollback-candidate; then
        say "Предыдущий IPK автоматически восстановлен." "The previous IPK was restored automatically."
    else
        say "Автоматический IPK-откат пока недоступен; сохранён бэкап конфигурации." "Automatic IPK rollback is not available yet; a configuration backup was saved."
    fi
    return 1
}

repair_interrupted_nfqws_bootstrap() {
    feed=/opt/etc/opkg/nfqws2-keenetic.conf
    [ -f "$feed" ] || return 0
    if /opt/bin/opkg status wget-ssl 2>/dev/null | grep -q '^Status:.* installed'; then
        return 0
    fi
    say "Обнаружена незавершённая настройка nfqws2. Сначала восстанавливаю поддержку HTTPS..." "An incomplete nfqws2 setup was found. Restoring HTTPS support first..."
    saved_feed="$TMP_DIR/nfqws2-keenetic.conf"
    NFQWS_SAVED_FEED=$saved_feed
    mv "$feed" "$saved_feed"
    /opt/bin/opkg update || die "не удалось обновить пакеты Entware при восстановлении HTTPS" "could not update Entware package lists while restoring HTTPS"
    /opt/bin/opkg install ca-certificates wget-ssl || die "не удалось установить wget с поддержкой HTTPS" "could not install wget with HTTPS support"
    /opt/bin/opkg remove wget-nossl >/dev/null 2>&1 || true
    mv "$saved_feed" "$feed"
    NFQWS_SAVED_FEED=
}

choose_install_language
[ "$(id -u)" = "0" ] || die "запустите установщик от пользователя root" "run the installer as root"
TMP_BASE=${TMPDIR:-/tmp}
case "$TMP_BASE" in
    /*) ;;
    *) die "TMPDIR должен быть абсолютным путём" "TMPDIR must be an absolute path" ;;
esac
[ "$TMP_BASE" != "/" ] || die "TMPDIR не должен указывать на корневой каталог" "TMPDIR must not point to the root directory"
TMP_DIR=$(mktemp -d "$TMP_BASE/mykeenpbr-install.XXXXXX") ||
    die "не удалось создать защищённый временный каталог" "could not create a private temporary directory"
case "$TMP_DIR" in
    "$TMP_BASE"/mykeenpbr-install.*) ;;
    *) die "mktemp вернул небезопасный путь" "mktemp returned an unsafe path" ;;
esac
chmod 0700 "$TMP_DIR" || die "не удалось защитить временный каталог" "could not set permissions on the temporary directory"
acquire_update_lock || die "другое обновление или откат keen-pbr-sb уже выполняется" "another keen-pbr-sb update or rollback is already running"
if [ "$AUTH_SETUP_ONLY" = 1 ]; then
    configure_web_auth
    say "Пакет, настройки DNS, VPN и nfqws2 не изменены." "The package, DNS, VPN and nfqws2 settings were not changed."
    say "Откройте прежний адрес панели и обновите страницу." "Open the same panel address and refresh the page."
    exit 0
fi
detect_target
if [ "$UPDATE_ONLY" = "0" ]; then
    repair_interrupted_nfqws_bootstrap
fi
ensure_release_verifier
say "Установка keen-pbr-sb для ${KEEN_ARCH}-${KEEN_ABI} из $PROJECT_REPOSITORY" "Installing keen-pbr-sb for ${KEEN_ARCH}-${KEEN_ABI} from $PROJECT_REPOSITORY"
download_package
say "Выбран выпуск $RELEASE_TAG. Пакет: $(basename "$PACKAGE_FILE")" "Selected release $RELEASE_TAG. Package: $(basename "$PACKAGE_FILE")"
bootstrap_rescue_helpers
if [ "$UPDATE_ONLY" = "1" ]; then
    say "Устанавливаю обновление keen-pbr-sb без изменения пользовательских настроек..." "Installing the keen-pbr-sb update without changing user settings..."
    install_package_transactionally
    say "Обновление keen-pbr-sb установлено. Веб-интерфейс перезапускается." "keen-pbr-sb has been updated. The web interface is restarting."
    exit 0
fi
prepare_first_install_retry
choose_optional_setup
choose_sing_box
/opt/bin/opkg update
prepare_first_install_dns
install_package_transactionally
set_sing_box_path
configure_web_auth
if [ "$DNS_BOOTSTRAP" != 1 ]; then configure_dns; fi
configure_nfqws2

say ""
say "Установка завершена." "Installation complete."
say "Веб-интерфейс: http://my.keenetic.net:12121/" "Web interface: http://my.keenetic.net:12121/"
say "Каталог конфигурации и резервных копий: /opt/etc/keen-pbr" "Configuration and backup directory: /opt/etc/keen-pbr"

#!/bin/sh

set -eu
umask 077

PROJECT_REPOSITORY="${MYKEENPBR_REPOSITORY:-blindtechnique/keen-pbr-sb}"
TRUSTED_RELEASE_REPOSITORY="blindtechnique/keen-pbr-sb"
GITHUB_API="https://api.github.com/repos"
SING_BOX_PINNED_VERSION="1.13.14"
TMP_DIR=
TRANSPORT_CONFIG="/opt/etc/keen-pbr/transports.json"
RESCUE_DIR="/opt/var/lib/keen-pbr/rescue"
RESCUE_HELPER="$RESCUE_DIR/rescue-update.sh"
LOCK_HELPER="$RESCUE_DIR/update-lock.sh"
METADATA_HELPER="$RESCUE_DIR/portable-stat.sh"
LOCK_DIR="/opt/var/run/keen-pbr-update.lock"
UPDATE_ONLY=0
REQUESTED_RELEASE_TAG=${KEEN_PBR_UPDATE_RELEASE_TAG:-}
# This one-shot handoff must not leak through opkg/postinst into new services.
unset KEEN_PBR_UPDATE_RELEASE_TAG
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
    # A failed HTTPS bootstrap must not discard the user's original feed with
    # the temporary downloads (including an interruption during opkg).
    if [ -n "${NFQWS_SAVED_FEED:-}" ] &&
       { [ -e "$NFQWS_SAVED_FEED" ] || [ -L "$NFQWS_SAVED_FEED" ]; }; then
        if mv "$NFQWS_SAVED_FEED" /opt/etc/opkg/nfqws2-keenetic.conf; then
            NFQWS_SAVED_FEED=
        else
            printf '%s\n' "Не удалось вернуть источник nfqws2. Копия сохранена: $NFQWS_SAVED_FEED" >&2
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
    printf '%s\n' "$*"
}

die() {
    say "ОШИБКА: $*" >&2
    exit 1
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
    say "Keenetic CLI не выполнил '$1':" >&2
    printf '%s\n' "$ndmc_output" >&2
    return "$ndmc_status"
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
case "$rv_channel" in stable|alpha|next) ;; *) release_verify_fail 'invalid channel' ;; esac
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
        die "Этот установщик проверяет только выпуски blindtechnique/keen-pbr-sb. Для другого проекта нужен его доверенный установщик."
    if ! command -v openssl >/dev/null 2>&1 && [ ! -x /opt/bin/openssl ]; then
        [ "$UPDATE_ONLY" = "0" ] ||
            die "Не найден OpenSSL для проверки выпуска. Установите пакет Entware openssl-util и повторите обновление."
        say "Устанавливаю OpenSSL для проверки подписи пакета..."
        /opt/bin/opkg update && /opt/bin/opkg install openssl-util ||
            die "Не удалось установить OpenSSL для проверки подписи. Установка keen-pbr-sb не началась."
    fi
    prepare_release_verifier
}

download_package() {
    [ "$PROJECT_REPOSITORY" = "$TRUSTED_RELEASE_REPOSITORY" ] ||
        die "Этот установщик проверяет только выпуски blindtechnique/keen-pbr-sb. Для другого проекта нужен его доверенный установщик."
    release_json="$TMP_DIR/release.json"
    release_url="$GITHUB_API/$PROJECT_REPOSITORY/releases/latest"
    if [ -n "$REQUESTED_RELEASE_TAG" ]; then
        case "$REQUESTED_RELEASE_TAG" in
            *[!A-Za-z0-9._-]*) die "Получен некорректный тег обновления. Пакет не загружен; повторите проверку обновлений." ;;
        esac
        release_url="$GITHUB_API/$PROJECT_REPOSITORY/releases/tags/$REQUESTED_RELEASE_TAG"
    fi
    fetch "$release_url" "$release_json"
    RELEASE_TAG=$(tr ',' '\n' < "$release_json" \
        | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
        | head -n 1)
    case "$RELEASE_TAG" in
        ""|*[!A-Za-z0-9._-]*) die "GitHub вернул некорректный тег выпуска" ;;
    esac
    if [ -n "$REQUESTED_RELEASE_TAG" ] && [ "$RELEASE_TAG" != "$REQUESTED_RELEASE_TAG" ]; then
        die "GitHub вернул другой выпуск. Пакет не загружен; повторите проверку обновлений."
    fi
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

    release_base="https://github.com/$TRUSTED_RELEASE_REPOSITORY/releases/download/$RELEASE_TAG"
    fetch "$release_base/release-manifest.tsv" "$TMP_DIR/release-manifest.tsv"
    fetch "$release_base/release-manifest.sig" "$TMP_DIR/release-manifest.sig"
    /bin/sh "$RELEASE_VERIFIER" "$TMP_DIR/release-manifest.tsv" \
        "$TMP_DIR/release-manifest.sig" "$RELEASE_PUBLIC_KEY" \
        "$TRUSTED_RELEASE_REPOSITORY" stable "$RELEASE_TAG" \
        package "$KEEN_ARCH" "$KEEN_ABI" "$(basename "$PACKAGE_FILE")" "$PACKAGE_FILE" ||
        die "Подпись пакета не подтверждена. Установка не началась; попробуйте загрузить выпуск позднее."
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
        ./opt/usr/lib/keen-pbr/portable-stat.sh \
        ./opt/usr/lib/keen-pbr/rescue-update.sh \
        ./opt/usr/lib/keen-pbr/rescue-startup-guard.sh \
        ./opt/usr/lib/keen-pbr/update-lock.sh ||
        die "проверенный IPK не содержит rescue helper"
    rescue_source="$helper_tree/opt/usr/lib/keen-pbr/rescue-update.sh"
    startup_guard_source="$helper_tree/opt/usr/lib/keen-pbr/rescue-startup-guard.sh"
    lock_source="$helper_tree/opt/usr/lib/keen-pbr/update-lock.sh"
    metadata_source="$helper_tree/opt/usr/lib/keen-pbr/portable-stat.sh"
    [ -f "$rescue_source" ] && [ ! -L "$rescue_source" ] &&
        [ -f "$startup_guard_source" ] &&
        [ ! -L "$startup_guard_source" ] &&
        [ -f "$lock_source" ] && [ ! -L "$lock_source" ] &&
        [ -f "$metadata_source" ] && [ ! -L "$metadata_source" ] ||
        die "rescue helper в IPK имеет небезопасный тип"
    /bin/sh -n "$rescue_source" || die "получен повреждённый rescue helper"
    /bin/sh -n "$startup_guard_source" ||
        die "получен повреждённый startup guard"
    /bin/sh -n "$lock_source" || die "получен повреждённый update lock helper"
    /bin/sh -n "$metadata_source" ||
        die "получен повреждённый metadata helper"

    [ ! -L "$RESCUE_DIR" ] &&
        { [ ! -e "$RESCUE_DIR" ] || [ -d "$RESCUE_DIR" ]; } ||
        die "каталог rescue имеет небезопасный тип"
    mkdir -p "$RESCUE_DIR"
    chmod 0700 "$RESCUE_DIR" || die "не удалось защитить каталог rescue"
    for helper in portable-stat.sh rescue-update.sh update-lock.sh; do
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
                printf '%s\n' "Не удалось вернуть sing-box. Предыдущие файлы сохранены: $sb_stage" >&2
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
                printf '%s\n' "Новый sing-box не запускается с ABI установленного Entware. Прежние файлы не изменены." >&2
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
        die "разрешена только зафиксированная версия sing-box $SING_BOX_PINNED_VERSION"
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
    publish_sing_box_candidate "$binary" ||
        die "Не удалось установить новый sing-box. Проверьте сообщение об ошибке выше и повторите установку."
    printf '%s\n' /opt/bin/sing-box > /opt/etc/keen-pbr/sing-box-managed.path
    SING_BOX_PATH=/opt/bin/sing-box
}

choose_sing_box() {
    existing=$(find_existing_sing_box || true)
    if [ -n "$existing" ]; then
        current=$(sing_box_version "$existing")
        say "Найден sing-box: $existing (версия ${current:-не определена})"
        say "  1) Использовать найденный файл (рекомендуется, если он уже проверен)"
        say "  2) Установить зафиксированную версию $SING_BOX_PINNED_VERSION в /opt/bin"
        say "  3) Указать другой существующий путь"
        say "  4) Продолжить без sing-box (только нативные интерфейсы)"
        choice=$(ask "Выберите [1-4] (по умолчанию 1):" "1")
    else
        say "sing-box не найден в стандартных каталогах."
        say "  1) Установить зафиксированную версию $SING_BOX_PINNED_VERSION в /opt/bin (рекомендуется)"
        say "  2) Указать другой существующий путь"
        say "  3) Продолжить без sing-box (только нативные интерфейсы)"
        choice=$(ask "Выберите [1-3] (по умолчанию 1):" "1")
        case "$choice" in 1) choice=2 ;; 2) choice=3 ;; 3) choice=4 ;; *) die "неверный выбор" ;; esac
    fi

    case "$choice" in
        1) SING_BOX_PATH="$existing" ;;
        2) install_sing_box "$SING_BOX_PINNED_VERSION" ;;
        3)
            SING_BOX_PATH=$(ask "Абсолютный путь к sing-box:" "")
            [ -x "$SING_BOX_PATH" ] || die "файл не является исполняемым: $SING_BOX_PATH"
            "$SING_BOX_PATH" version >/dev/null || die "выбранный sing-box не запускается"
            ;;
        4) SING_BOX_PATH="" ;;
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
            umask 077
            printf '%s\n' '{"enabled":true,"provider":"keenetic","keenetic_endpoint_mode":"auto","session_ttl_seconds":604800}' > "$auth_file"
            chmod 0600 "$auth_file"
            /opt/etc/init.d/S80keen-pbr restart
            say "Адрес и порт веб-интерфейса будут безопасно определены через локальный NDMS RCI."
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
        say "ПРЕДУПРЕЖДЕНИЕ: не удалось сохранить восстановленную настройку DNS в Keenetic." >&2
        restored=N
    fi
    if [ "$restart_attempted" = Y ] && [ "$was_running" = Y ]; then
        /opt/etc/init.d/S56dnsmasq start >/dev/null 2>&1 || restored=N
    fi
    [ "$restored" = Y ]
}

configure_dns() {
    answer=$(ask "Включить Keenetic DNS Override и настроить dnsmasq Entware? [Y/n]:" "Y")
    case "$answer" in
        n|N|no|NO) return 0 ;;
    esac

    previous_override=$(read_dns_override_state) ||
        die "не удалось прочитать текущее состояние DNS Override; настройки DNS не изменены"
    dns_was_running=N
    if pidof dnsmasq >/dev/null 2>&1; then dns_was_running=Y; fi
    template=/opt/usr/lib/keen-pbr/dnsmasq.conf.template
    config=/opt/etc/dnsmasq.conf
    [ -f "$template" ] || die "шаблон dnsmasq отсутствует"
    /opt/sbin/dnsmasq --test --conf-file="$template" >/dev/null 2>&1 || die "сгенерированная конфигурация dnsmasq некорректна"
    # Keep an operator's symlink itself unchanged. Publish beside its resolved
    # target so rename stays on the same filesystem even for a custom target.
    if [ -L "$config" ]; then
        config=$(readlink -f "$config") && [ -n "$config" ] ||
            die "не удалось определить файл конфигурации dnsmasq; настройки DNS не изменены"
    fi
    [ ! -e "$config" ] || [ -f "$config" ] ||
        die "конфигурация dnsmasq не является обычным файлом; настройки DNS не изменены"
    backup="$config.backup-mykeenpbr-$(date +%Y%m%d%H%M%S)"
    had_config=N
    if [ -f "$config" ]; then
        cp -p "$config" "$backup" ||
            die "не удалось сохранить прежнюю конфигурацию dnsmasq; настройки DNS не изменены"
        had_config=Y
    fi

    # Never truncate the working file before the new bytes and permissions are
    # ready. ENOSPC, chmod and rename failures leave the old DNS state intact.
    candidate=$(mktemp "$config.new-mykeenpbr.XXXXXX") ||
        die "не удалось подготовить конфигурацию dnsmasq; настройки DNS не изменены"
    if ! cp "$template" "$candidate" ||
       ! chmod 0600 "$candidate" ||
       ! mv -f "$candidate" "$config"; then
        rm -f "$candidate" || true
        die "не удалось записать конфигурацию dnsmasq; настройки DNS не изменены"
    fi
    if ! run_ndmc "opkg dns-override" ||
       ! run_ndmc "system configuration save"; then
        restore_dns_setup "$previous_override" "$dns_was_running" \
            "$config" "$backup" "$had_config" N ||
            say "ПРЕДУПРЕЖДЕНИЕ: восстановление прежнего DNS завершено не полностью; проверьте DNS в Keenetic." >&2
        die "не удалось включить opkg dns-override"
    fi
    if ! /opt/etc/init.d/S56dnsmasq restart >/dev/null 2>&1; then
        restore_dns_setup "$previous_override" "$dns_was_running" \
            "$config" "$backup" "$had_config" Y ||
            say "ПРЕДУПРЕЖДЕНИЕ: восстановление прежнего DNS завершено не полностью; проверьте DNS в Keenetic." >&2
        die "dnsmasq не запустился; выполнен возврат к прежним настройкам DNS"
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

    if PKG_UPGRADE=1 \
           KEEN_PBR_RESCUE_TRANSACTION=1 \
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
    NFQWS_SAVED_FEED=$saved_feed
    mv "$feed" "$saved_feed"
    /opt/bin/opkg update || die "не удалось обновить пакеты Entware при восстановлении HTTPS"
    /opt/bin/opkg install ca-certificates wget-ssl || die "не удалось установить wget с поддержкой HTTPS"
    /opt/bin/opkg remove wget-nossl >/dev/null 2>&1 || true
    mv "$saved_feed" "$feed"
    NFQWS_SAVED_FEED=
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
if [ "$UPDATE_ONLY" = "0" ]; then
    repair_interrupted_nfqws_bootstrap
fi
ensure_release_verifier
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

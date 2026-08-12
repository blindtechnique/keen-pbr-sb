#!/bin/sh

# Read file metadata with either GNU coreutils stat or the reduced BusyBox
# implementation shipped by Entware on Keenetic. Keep this helper source-only:
# callers retain their own error handling and fail-closed policy.

keen_pbr_run_stat() {
    if [ -x "${ROOT:-}/opt/bin/stat" ]; then
        "${ROOT:-}/opt/bin/stat" "$@"
    elif [ -x "${ROOT:-}/opt/bin/busybox" ]; then
        "${ROOT:-}/opt/bin/busybox" stat "$@"
    elif command -v stat >/dev/null 2>&1; then
        stat "$@"
    elif command -v busybox >/dev/null 2>&1; then
        busybox stat "$@"
    else
        return 1
    fi
}

keen_pbr_decode_terse_stat() {
    keen_pbr_terse_target=${1:-}
    keen_pbr_terse_output=${2:-}
    case "$keen_pbr_terse_output" in
        "$keen_pbr_terse_target "*)
            keen_pbr_stat_fields=${keen_pbr_terse_output#"$keen_pbr_terse_target "}
            ;;
        *)
            return 1
            ;;
    esac

    set -- $keen_pbr_stat_fields
    [ "$#" -ge 5 ] || return 1
    keen_pbr_stat_mode_hex=$3
    keen_pbr_stat_uid=$4
    keen_pbr_stat_gid=$5
    case "$keen_pbr_stat_mode_hex" in
        ''|*[!0-9A-Fa-f]*) return 1 ;;
    esac
    [ "${#keen_pbr_stat_mode_hex}" -le 8 ] || return 1
    case "$keen_pbr_stat_uid" in
        ''|*[!0-9]*) return 1 ;;
    esac
    case "$keen_pbr_stat_gid" in
        ''|*[!0-9]*) return 1 ;;
    esac

    keen_pbr_stat_mode_decimal=$((0x$keen_pbr_stat_mode_hex & 4095))
    KEEN_PBR_STAT_MODE=$(
        printf '%o' "$keen_pbr_stat_mode_decimal"
    ) || return 1
    KEEN_PBR_STAT_UID=$keen_pbr_stat_uid
    KEEN_PBR_STAT_GID=$keen_pbr_stat_gid
}

keen_pbr_read_stat_metadata() {
    KEEN_PBR_STAT_MODE=
    KEEN_PBR_STAT_UID=
    KEEN_PBR_STAT_GID=

    keen_pbr_stat_target=${1:-}
    [ -n "$keen_pbr_stat_target" ] || return 1

    # BusyBox and GNU stat both support terse output for ordinary managed
    # paths. Trying it first avoids one guaranteed failed process on Keenetic.
    keen_pbr_stat_output=$(
        LC_ALL=C keen_pbr_run_stat \
            -t "$keen_pbr_stat_target" 2>/dev/null
    ) || keen_pbr_stat_output=
    if keen_pbr_decode_terse_stat \
        "$keen_pbr_stat_target" "$keen_pbr_stat_output"; then
        return 0
    fi

    # GNU stat may quote unusual filenames in terse mode. Its explicit format
    # is an unambiguous fallback; reduced BusyBox builds simply reject it.
    keen_pbr_stat_output=$(
        LC_ALL=C keen_pbr_run_stat \
            -c '%a:%u:%g' "$keen_pbr_stat_target" 2>/dev/null
    ) || return 1
    case "$keen_pbr_stat_output" in
        [0-7]*:[0-9]*:[0-9]*)
            keen_pbr_stat_mode=${keen_pbr_stat_output%%:*}
            keen_pbr_stat_owner_group=${keen_pbr_stat_output#*:}
            keen_pbr_stat_uid=${keen_pbr_stat_owner_group%%:*}
            keen_pbr_stat_gid=${keen_pbr_stat_owner_group#*:}
            case "$keen_pbr_stat_mode" in
                ''|*[!0-7]*) return 1 ;;
            esac
            case "$keen_pbr_stat_uid" in
                ''|*[!0-9]*) return 1 ;;
            esac
            case "$keen_pbr_stat_gid" in
                ''|*[!0-9]*) return 1 ;;
            esac
            KEEN_PBR_STAT_MODE=$keen_pbr_stat_mode
            KEEN_PBR_STAT_UID=$keen_pbr_stat_uid
            KEEN_PBR_STAT_GID=$keen_pbr_stat_gid
            return 0
            ;;
    esac
    return 1
}

keen_pbr_stat_value() {
    keen_pbr_stat_format=${1:-}
    keen_pbr_stat_path=${2:-}
    keen_pbr_read_stat_metadata "$keen_pbr_stat_path" || return 1
    case "$keen_pbr_stat_format" in
        %a) printf '%s\n' "$KEEN_PBR_STAT_MODE" ;;
        %u) printf '%s\n' "$KEEN_PBR_STAT_UID" ;;
        %g) printf '%s\n' "$KEEN_PBR_STAT_GID" ;;
        %a:%u)
            printf '%s:%s\n' \
                "$KEEN_PBR_STAT_MODE" "$KEEN_PBR_STAT_UID"
            ;;
        %a:%u:%g)
            printf '%s:%s:%s\n' \
                "$KEEN_PBR_STAT_MODE" \
                "$KEEN_PBR_STAT_UID" \
                "$KEEN_PBR_STAT_GID"
            ;;
        %u:%g:%a)
            printf '%s:%s:%s\n' \
                "$KEEN_PBR_STAT_UID" \
                "$KEEN_PBR_STAT_GID" \
                "$KEEN_PBR_STAT_MODE"
            ;;
        *) return 1 ;;
    esac
}

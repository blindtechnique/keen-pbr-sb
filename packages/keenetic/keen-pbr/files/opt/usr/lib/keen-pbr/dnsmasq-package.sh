#!/bin/sh

# Keep dnsmasq independent while opkg replaces/removes our conf-script. The
# small block in dnsmasq.conf is configuration, not another recovery journal.
set -eu
ROOT=${KEEN_PBR_RESCUE_ROOT:-}
DNS_CONFIG="${ROOT}/opt/etc/dnsmasq.conf"
FALLBACK_CONFIG="${ROOT}/opt/etc/keen-pbr/dnsmasq-fallback.conf"
BLOCK_BEGIN='# BEGIN keen-pbr standalone DNS fallback v1'
BLOCK_END='# END keen-pbr standalone DNS fallback v1'
MANAGED_SCRIPT='conf-script=/opt/usr/lib/keen-pbr/dnsmasq.sh dnsmasq-config-entry'
CANDIDATE=
VISITED=
trap '[ -z "$CANDIDATE" ] || rm -f "$CANDIDATE"' EXIT

normalize_directive() {
    printf '%s\n' "$1" | sed 's/\r$//; s/^[[:space:]]*//; s/[[:space:]]*=[[:space:]]*/=/; s/[[:space:]]*$//'
}

is_managed_script() {
    local directive
    directive=$(normalize_directive "$1")
    case "$directive" in
        "$MANAGED_SCRIPT"|"$MANAGED_SCRIPT #"*) return 0 ;;
        *) return 1 ;;
    esac
}

is_owned_include() {
    case "$1" in /opt/etc/keen-pbr/*) return 0 ;; *) return 1 ;; esac
}

directory_file_selected() {
    local name="$1" filters="$2" suffix inclusive=no included=no
    case "$name" in .*|*~|\#*\#) return 1 ;; esac
    while [ -n "$filters" ]; do
        suffix=${filters%%,*}
        if [ "$suffix" = "$filters" ]; then filters=; else filters=${filters#*,}; fi
        case "$suffix" in
            \**)
                inclusive=yes
                suffix=${suffix#\*}
                case "$name" in *"$suffix") included=yes ;; esac
                ;;
            '') ;;
            *) case "$name" in *"$suffix") return 1 ;; esac ;;
        esac
    done
    [ "$inclusive" = no ] || [ "$included" = yes ]
}

emit_dns_directory() {
    local specification="$1" directory filters file
    directory=${specification%%,*}
    filters=
    [ "$directory" = "$specification" ] || filters=${specification#*,}
    [ -d "$ROOT$directory" ] || return 1
    # Shell globbing gives the same alphabetical order; dot files are skipped
    # by dnsmasq as well. Preserve its include/exclude suffix semantics.
    for file in "$ROOT$directory"/*; do
        [ -f "$file" ] || continue
        directory_file_selected "${file##*/}" "$filters" || continue
        emit_dns_file "$file" || return 1
    done
}

emit_dns_file() {
    local file="$1" canonical line directive value directory
    canonical=$(readlink -f "$file") || return 1
    [ -f "$canonical" ] || return 1
    case "
$VISITED
" in *"
$canonical
"*) return 0 ;; esac
    VISITED="$VISITED
$canonical"
    while IFS= read -r line || [ -n "$line" ]; do
        directive=$(normalize_directive "$line")
        case "$directive" in
            ipset=*|nftset=*) continue ;;
            conf-file=*|servers-file=*)
                value=${directive#*=}
                # Quoted ordinary filenames are accepted too; do not evaluate
                # shell escapes or execute a provider/user-supplied script.
                case "$value" in \"*\") value=${value#\"}; value=${value%\"} ;; esac
                if is_owned_include "$value"; then
                    emit_dns_file "$ROOT$value" || return 1
                    continue
                fi
                ;;
            conf-dir=*)
                value=${directive#*=}
                directory=${value%%,*}
                case "$directory" in
                    \"*\")
                        directory=${directory#\"}; directory=${directory%\"}
                        if [ "$value" = "${value%%,*}" ]; then
                            value=$directory
                        else
                            value="$directory,${value#*,}"
                        fi
                        ;;
                esac
                if is_owned_include "$directory/"; then
                    emit_dns_directory "$value" || return 1
                    continue
                fi
                ;;
            conf-script=*)
                # A script below the removed package cannot remain a DNS
                # dependency. Its active routing output is not a direct reserve.
                case "$directive" in
                    conf-script=/opt/usr/lib/keen-pbr/*|conf-script=/opt/etc/keen-pbr/*)
                        echo "Cannot preserve a package-local DNS conf-script: $directive" >&2
                        return 1
                        ;;
                esac
                ;;
        esac
        printf '%s\n' "$line"
    done < "$canonical"
}

write_detached_config() {
    local line emitted=no
    while IFS= read -r line || [ -n "$line" ]; do
        if is_managed_script "$line"; then
            [ "$emitted" = no ] || continue
            printf '%s\n' "$BLOCK_BEGIN"
            if [ -f "$FALLBACK_CONFIG" ]; then
                emit_dns_file "$FALLBACK_CONFIG" || return 1
            else
                echo '# No direct fallback was configured; no public DNS was substituted.'
            fi
            printf '%s\n' "$BLOCK_END"
            emitted=yes
        else
            printf '%s\n' "$line"
        fi
    done < "$DNS_CONFIG"
}

write_attached_config() {
    local line directive inside=no
    while IFS= read -r line || [ -n "$line" ]; do
        directive=$(normalize_directive "$line")
        if [ "$directive" = "$BLOCK_BEGIN" ]; then
            [ "$inside" = no ] || return 1
            inside=yes
            printf '%s\n' "$MANAGED_SCRIPT"
        elif [ "$directive" = "$BLOCK_END" ]; then
            [ "$inside" = yes ] || return 1
            inside=no
        elif [ "$inside" = no ]; then
            printf '%s\n' "$line"
        fi
    done < "$DNS_CONFIG"
    [ "$inside" = no ]
}

case "${1:-}" in
    detach|restore) action=$1 ;;
    *) echo "Usage: $0 {detach|restore}" >&2; exit 2 ;;
esac
[ -f "$DNS_CONFIG" ] || exit 0
# Keep a user's symlink and its target mode/ownership instead of replacing the
# symlink with a new regular config file.
DNS_CONFIG=$(readlink -f "$DNS_CONFIG") || exit 1
if [ "$action" = detach ]; then
    found=no
    while IFS= read -r line || [ -n "$line" ]; do
        if is_managed_script "$line"; then found=yes; break; fi
    done < "$DNS_CONFIG"
    [ "$found" = yes ] || exit 0
else
    grep -Fq "$BLOCK_BEGIN" "$DNS_CONFIG" || exit 0
fi
CANDIDATE=$(mktemp "${DNS_CONFIG}.keen-pbr.XXXXXX") || exit 1
cp -p "$DNS_CONFIG" "$CANDIDATE" || exit 1
if [ "$action" = detach ]; then
    write_detached_config > "$CANDIDATE" || exit 1
else
    write_attached_config > "$CANDIDATE" || exit 1
fi
if [ -x "$ROOT/opt/sbin/dnsmasq" ]; then
    "$ROOT/opt/sbin/dnsmasq" --test --conf-file="$CANDIDATE" || exit 1
fi
mv -f "$CANDIDATE" "$DNS_CONFIG" || exit 1
CANDIDATE=
# postinst starts S80 afterwards, which activates and restarts the resolver.
# prerm must leave already running dnsmasq independent before opkg unlinks us.
if [ "$action" = detach ] && [ -x "$ROOT/opt/etc/init.d/S56dnsmasq" ]; then
    "$ROOT/opt/usr/lib/keen-pbr/dnsmasq.sh" restart-dnsmasq
fi

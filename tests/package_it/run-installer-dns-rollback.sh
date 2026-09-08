#!/bin/sh

set -eu
[ "$#" -eq 1 ] || { echo "usage: $0 <install.sh>" >&2; exit 2; }
source_script=$1
workdir=$(mktemp -d /tmp/keen-pbr-install-dns.XXXXXX)
trap 'rm -rf "$workdir"' EXIT HUP INT TERM

# Execute the shipped function bodies; replace only fixed filesystem/command
# boundaries. No installer entrypoint, router paths, services or network calls.
for function_name in read_dns_override_state restore_dns_setup configure_dns; do
    definition=$(sed -n "/^${function_name}() {/,/^}/p" "$source_script" |
        sed -e "s@/opt/usr/lib/keen-pbr/dnsmasq.conf.template@$workdir/template@g" \
            -e "s@/opt/etc/dnsmasq.conf@$workdir/dnsmasq.conf@g" \
            -e 's@/opt/etc/init.d/S56dnsmasq@fake_dnsmasq_service@g' \
            -e 's@/opt/sbin/dnsmasq@fake_dnsmasq_test@g')
    [ -n "$definition" ] || { echo "Missing function $function_name" >&2; exit 1; }
    eval "$definition"
done

fail() { echo "$*" >&2; exit 1; }
say() { printf '%s\n' "$*"; }
die() { say "$*" >&2; exit 1; }
ask() { printf '%s\n' "$answer_value"; }
pidof() { [ "$(cat "$workdir/running")" = Y ]; }
nslookup() { return 0; }
fake_dnsmasq_test() { [ "$failure" != validate ]; }

cp() {
    if [ "$failure" = copy ] && [ "$#" -eq 2 ] &&
       [ "$1" = "$workdir/template" ]; then
        printf '# partial write before ENOSPC\n' > "$2"
        return 1
    fi
    command cp "$@"
}

chmod() {
    if [ "$failure" = chmod ]; then
        case "$2" in "$workdir/"*.new-mykeenpbr.*) return 1 ;; esac
    fi
    command chmod "$@"
}

mv() {
    if [ "$failure" = rename ]; then
        case "$2" in "$workdir/"*.new-mykeenpbr.*) return 1 ;; esac
    fi
    command mv "$@"
}

run_ndmc() {
    printf '%s\n' "$1" >> "$workdir/commands"
    case "$1" in
        'show running-config')
            ndmc_output="! running configuration
ip http proxy dns-override
user secret-fixture-only"
            if [ "$failure" = read ]; then
                echo "$ndmc_output" >&2
                return 1
            fi
            if [ "$(cat "$workdir/override")" = Y ]; then
                ndmc_output="$ndmc_output
opkg dns-override"
            fi
            ;;
        'opkg dns-override')
            printf 'Y\n' > "$workdir/override"
            if [ "$failure" = enable ] && [ ! -e "$workdir/failed" ]; then
                touch "$workdir/failed"
                return 1
            fi
            ;;
        'no opkg dns-override') printf 'N\n' > "$workdir/override" ;;
        'system configuration save')
            if [ "$failure" = save ] && [ ! -e "$workdir/failed" ]; then
                touch "$workdir/failed"
                return 1
            fi
            ;;
        *) return 2 ;;
    esac
}

fake_dnsmasq_service() {
    printf 'service %s\n' "$1" >> "$workdir/commands"
    case "$1" in
        stop) printf 'N\n' > "$workdir/running" ;;
        start) printf 'Y\n' > "$workdir/running" ;;
        restart)
            printf 'N\n' > "$workdir/running"
            [ "$failure" != restart ] || return 1
            printf 'Y\n' > "$workdir/running"
            ;;
        *) return 2 ;;
    esac
}

run_case() {
    failure=$1
    initial_override=$2
    initial_running=$3
    initial_file=$4
    answer_value=Y
    [ "$failure" != declined ] || answer_value=N
    rm -f "$workdir/failed" "$workdir/dnsmasq.conf" "$workdir/linked-dnsmasq.conf"
    : > "$workdir/commands"
    printf '%s\n' "$initial_override" > "$workdir/override"
    printf '%s\n' "$initial_running" > "$workdir/running"
    printf 'server=9.9.9.9\n' > "$workdir/template"
    if [ "$initial_file" != N ]; then
        if [ "$initial_file" = L ]; then
            ln -s linked-dnsmasq.conf "$workdir/dnsmasq.conf"
        fi
        printf '# operator config\nserver=127.0.0.1#40508\n' > "$workdir/dnsmasq.conf"
        chmod 0640 "$workdir/dnsmasq.conf"
        cp -p "$workdir/dnsmasq.conf" "$workdir/expected"
    fi
    # A function invoked on the left of || ignores set -e throughout its body.
    # Run a non-conditional subshell with its own errexit, then collect status.
    set +e
    (set -e; configure_dns) > "$workdir/out" 2> "$workdir/err"
    result=$?
    set -e
    if [ "$failure" = none ]; then
        [ "$result" -eq 0 ] || fail 'successful setup failed'
        [ "$(cat "$workdir/override")" = Y ] || fail 'setup did not enable override'
        [ "$(cat "$workdir/running")" = Y ] || fail 'setup did not start dnsmasq'
        cmp -s "$workdir/template" "$workdir/dnsmasq.conf" || fail 'template not applied'
    else
        if [ "$failure" = declined ]; then
            [ "$result" -eq 0 ] || fail 'declined optional setup failed'
            [ ! -s "$workdir/commands" ] || fail 'declined setup ran a command'
        else
            [ "$result" -ne 0 ] || fail "$failure unexpectedly succeeded"
        fi
        [ "$(cat "$workdir/override")" = "$initial_override" ] || fail "$failure changed override"
        [ "$(cat "$workdir/running")" = "$initial_running" ] || fail "$failure changed previous runtime"
        if [ "$initial_file" != N ]; then
            cmp -s "$workdir/expected" "$workdir/dnsmasq.conf" || fail "$failure changed previous config"
            [ "$(stat -L -c '%a' "$workdir/dnsmasq.conf")" = 640 ] || fail "$failure changed permissions"
        else
            [ ! -e "$workdir/dnsmasq.conf" ] || fail "$failure left a new config behind"
        fi
        if [ "$failure" != restart ]; then
            ! grep -q '^service ' "$workdir/commands" || fail "$failure unnecessarily restarted DNS"
        fi
    fi
    if [ "$initial_file" = L ]; then
        [ -L "$workdir/dnsmasq.conf" ] || fail "$failure replaced the operator symlink"
        [ "$(readlink "$workdir/dnsmasq.conf")" = linked-dnsmasq.conf ] ||
            fail "$failure changed the symlink target"
    fi
    case "$failure" in
        copy|chmod|rename)
            ! grep -q '^\(no opkg\|opkg\|system\|service\) ' "$workdir/commands" ||
                fail "$failure changed DNS before file publication"
            ;;
    esac
    [ -z "$(find "$workdir" -name '*.new-mykeenpbr.*' -print)" ] ||
        fail "$failure left a candidate file behind"
    ! grep -q 'secret-fixture-only' "$workdir/out" "$workdir/err" || fail 'running config leaked'
}

run_case none N N N
run_case save N N Y
run_case save Y Y L
run_case save N N N
run_case enable N Y Y
run_case restart N N N
run_case restart Y Y Y
run_case read N Y Y
run_case validate Y Y Y
run_case declined N Y Y
run_case copy Y Y Y
run_case chmod Y Y L
run_case rename N N N
run_case none Y Y L
echo 'installer DNS rollback: 14 cases passed (mocked commands, no router mutation)'

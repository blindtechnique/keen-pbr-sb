#!/bin/sh

set -eu

init_script=${1:-}
[ -f "$init_script" ] || {
    echo "usage: $0 <S80keen-pbr>" >&2
    exit 2
}

work=$(mktemp -d)
trap 'rm -rf "$work"' 0 HUP INT TERM

# Source the bounded xtables transaction and the production PPE ownership
# parser without executing rc.func's dispatcher.
sed -n '/^run_bounded_command()/,/^is_module_loaded()/p' \
    "$init_script" | sed '$d' > "$work/functions.sh"

mkdir -p "$work/bin" "$work/state"
cat > "$work/bin/iptables" <<'EOF'
#!/bin/sh

state=$(cat "$PPE_TEST_STATE")
printf 'iptables %s\n' "$*" >> "$PPE_TEST_LOG"
[ "$*" = '-w -t mangle -S' ] || {
    echo "unexpected iptables call: $*" >&2
    exit 90
}

case "$state" in
    absent) exit 0 ;;
    exact|restore-fail|remains|concurrent-stray)
        cat <<'RULES'
-N KeenPbrPpe4
-A PREROUTING -m comment --comment "keen-pbr-sb:ppe:prerouting" -j KeenPbrPpe4
-A FORWARD -m comment --comment "keen-pbr-sb:ppe:forward" -j KeenPbrPpe4
-A KeenPbrPpe4 -p tcp -m tcp -m multiport --dports 80,443,1984,2053,2083,2087,2096,5222,8443 -m connskip --connskip 30 -m comment --comment "keen-pbr-sb:ppe:tcp:0" -j PPE
-A KeenPbrPpe4 -p udp -m udp --dport 443 -m connskip --connskip 30 -m comment --comment "keen-pbr-sb:ppe:quic" -j PPE
-A KeenPbrPpe4 -m comment --comment "keen-pbr-sb:ppe:return" -j RETURN
RULES
        if [ "$state" = concurrent-stray ]; then
            printf '%s\n' concurrent-stray-mutated > "$PPE_TEST_STATE"
        fi
        ;;
    duplicate)
        cat <<'RULES'
-N KeenPbrPpe4
-A PREROUTING -m comment --comment keen-pbr-sb:ppe:prerouting -j KeenPbrPpe4
-A PREROUTING -m comment --comment keen-pbr-sb:ppe:prerouting -j KeenPbrPpe4
-A FORWARD -m comment --comment keen-pbr-sb:ppe:forward -j KeenPbrPpe4
-A FORWARD -m comment --comment keen-pbr-sb:ppe:forward -j KeenPbrPpe4
-A KeenPbrPpe4 -p tcp -m multiport --dports 80,443 -m connskip --connskip 30 -m comment --comment keen-pbr-sb:ppe:tcp:0 -j PPE
-A KeenPbrPpe4 -m comment --comment keen-pbr-sb:ppe:return -j RETURN
RULES
        ;;
    foreign|foreign-goto)
        foreign_jump='-j'
        [ "$state" != foreign-goto ] || foreign_jump='-g'
        cat <<'RULES'
-N KeenPbrPpe4
-A PREROUTING -m comment --comment keen-pbr-sb:ppe:prerouting -j KeenPbrPpe4
-A FORWARD -m comment --comment keen-pbr-sb:ppe:forward -j KeenPbrPpe4
RULES
        printf '%s\n' "-A ForeignChain $foreign_jump KeenPbrPpe4"
        cat <<'RULES'
-A KeenPbrPpe4 -p tcp -m multiport --dports 443 -m connskip --connskip 30 -m comment --comment keen-pbr-sb:ppe:tcp:0 -j PPE
-A KeenPbrPpe4 -m comment --comment keen-pbr-sb:ppe:return -j RETURN
RULES
        ;;
    malformed)
        cat <<'RULES'
-N KeenPbrPpe4
-A PREROUTING -m comment --comment keen-pbr-sb:ppe:prerouting -j KeenPbrPpe4
-A FORWARD -m comment --comment keen-pbr-sb:ppe:forward -j KeenPbrPpe4
-A KeenPbrPpe4 -p tcp --dport 443 -j ACCEPT
RULES
        ;;
    noncanonical-ports)
        cat <<'RULES'
-N KeenPbrPpe4
-A PREROUTING -m comment --comment keen-pbr-sb:ppe:prerouting -j KeenPbrPpe4
-A FORWARD -m comment --comment keen-pbr-sb:ppe:forward -j KeenPbrPpe4
-A KeenPbrPpe4 -p tcp -m multiport --dports 443,80:81,82 -m connskip --connskip 30 -m comment --comment keen-pbr-sb:ppe:tcp:0 -j PPE
-A KeenPbrPpe4 -m comment --comment keen-pbr-sb:ppe:return -j RETURN
RULES
        ;;
    slot-overflow)
        cat <<'RULES'
-N KeenPbrPpe4
-A PREROUTING -m comment --comment keen-pbr-sb:ppe:prerouting -j KeenPbrPpe4
-A FORWARD -m comment --comment keen-pbr-sb:ppe:forward -j KeenPbrPpe4
-A KeenPbrPpe4 -p tcp -m multiport --dports 1:2,4:5,7:8,10:11,13:14,16:17,19:20,22:23 -m connskip --connskip 30 -m comment --comment keen-pbr-sb:ppe:tcp:0 -j PPE
-A KeenPbrPpe4 -m comment --comment keen-pbr-sb:ppe:return -j RETURN
RULES
        ;;
    quic-missing-module)
        cat <<'RULES'
-N KeenPbrPpe4
-A PREROUTING -m comment --comment keen-pbr-sb:ppe:prerouting -j KeenPbrPpe4
-A FORWARD -m comment --comment keen-pbr-sb:ppe:forward -j KeenPbrPpe4
-A KeenPbrPpe4 -p tcp -m multiport --dports 443 -m connskip --connskip 30 -m comment --comment keen-pbr-sb:ppe:tcp:0 -j PPE
-A KeenPbrPpe4 -p udp --dport 443 -m connskip --connskip 30 -m comment --comment keen-pbr-sb:ppe:quic -j PPE
-A KeenPbrPpe4 -m comment --comment keen-pbr-sb:ppe:return -j RETURN
RULES
        ;;
    noncontiguous-index)
        cat <<'RULES'
-N KeenPbrPpe4
-A PREROUTING -m comment --comment keen-pbr-sb:ppe:prerouting -j KeenPbrPpe4
-A FORWARD -m comment --comment keen-pbr-sb:ppe:forward -j KeenPbrPpe4
-A KeenPbrPpe4 -p tcp -m multiport --dports 443 -m connskip --connskip 30 -m comment --comment keen-pbr-sb:ppe:tcp:1 -j PPE
-A KeenPbrPpe4 -m comment --comment keen-pbr-sb:ppe:return -j RETURN
RULES
        ;;
    wrong-rule-order)
        cat <<'RULES'
-N KeenPbrPpe4
-A PREROUTING -m comment --comment keen-pbr-sb:ppe:prerouting -j KeenPbrPpe4
-A FORWARD -m comment --comment keen-pbr-sb:ppe:forward -j KeenPbrPpe4
-A KeenPbrPpe4 -p udp --dport 443 -m connskip --connskip 30 -m comment --comment keen-pbr-sb:ppe:quic -j PPE
-A KeenPbrPpe4 -p tcp -m multiport --dports 443 -m connskip --connskip 30 -m comment --comment keen-pbr-sb:ppe:tcp:0 -j PPE
-A KeenPbrPpe4 -m comment --comment keen-pbr-sb:ppe:return -j RETURN
RULES
        ;;
    reserved-stray)
        cat <<'RULES'
-N KeenPbrPpe4
-A PREROUTING -m comment --comment keen-pbr-sb:ppe:prerouting -j KeenPbrPpe4
-A FORWARD -m comment --comment keen-pbr-sb:ppe:forward -j KeenPbrPpe4
-A PREROUTING -p tcp --dport 443 -m comment --comment keen-pbr-sb:ppe:tcp:99 -j PPE
-A KeenPbrPpe4 -p tcp -m multiport --dports 443 -m connskip --connskip 30 -m comment --comment keen-pbr-sb:ppe:tcp:0 -j PPE
-A KeenPbrPpe4 -m comment --comment keen-pbr-sb:ppe:return -j RETURN
RULES
        ;;
    empty-reserved-stray)
        cat <<'RULES'
-N KeenPbrPpe4
-A OUTPUT -m comment --comment keen-pbr-sb:ppe:foreign -j PPE
RULES
        ;;
    no-chain-reserved-stray)
        printf '%s\n' '-A OUTPUT -m comment --comment keen-pbr-sb:ppe:foreign -j PPE'
        ;;
    quoted-reserved-stray)
        cat <<'RULES'
-N KeenPbrPpe4
-A OUTPUT -m comment --comment "keen-pbr-sb:ppe:foreign rule" -j PPE
RULES
        ;;
    empty-owned)
        printf '%s\n' '-N KeenPbrPpe4'
        ;;
    *) exit 91 ;;
esac
EOF

cat > "$work/bin/iptables-restore" <<'EOF'
#!/bin/sh

state=$(cat "$PPE_TEST_STATE")
payload=$(cat)
printf 'iptables-restore %s\n' "$*" >> "$PPE_TEST_LOG"
printf '%s\n' "$payload" | sed 's/^/stdin: /' >> "$PPE_TEST_LOG"
[ "$*" = '--noflush' ] || exit 92

case "$state" in
    restore-fail) exit 4 ;;
    remains) exit 0 ;;
    exact|duplicate|empty-owned)
        printf '%s\n' absent > "$PPE_TEST_STATE"
        exit 0
        ;;
    concurrent-stray-mutated)
        # A foreign writer appended after the exact snapshot. The safe
        # transaction contains only exact deletes and therefore fails at -X;
        # an unsafe flush would erase the foreign rule and falsely succeed.
        if printf '%s\n' "$payload" | grep -Fq -- '-F KeenPbrPpe4'; then
            printf '%s\n' absent > "$PPE_TEST_STATE"
            exit 0
        fi
        exit 4
        ;;
esac
exit 93
EOF
chmod +x "$work/bin/iptables" "$work/bin/iptables-restore"

PATH="$work/bin:$PATH"
PPE_TEST_STATE="$work/state/ppe"
PPE_TEST_LOG="$work/calls"
PPE_DEOFFLOAD_OWNERSHIP_FILE="$work/owner"
META_XTABLES_RESTORE_FILE="$work/restore.input"
IPTABLES_WAIT_MODE=flag
IPTABLES_BARE_WAIT_SECONDS=1
export PATH PPE_TEST_STATE PPE_TEST_LOG
export PPE_DEOFFLOAD_OWNERSHIP_FILE META_XTABLES_RESTORE_FILE

log_error() { :; }
. "$work/functions.sh"

reset_case() {
    printf '%s\n' "$1" > "$PPE_TEST_STATE"
    : > "$PPE_TEST_LOG"
    rm -f "$PPE_DEOFFLOAD_OWNERSHIP_FILE"
}

write_valid_owner() {
    printf '%s\n' iptables > "$PPE_DEOFFLOAD_OWNERSHIP_FILE"
    chmod 0600 "$PPE_DEOFFLOAD_OWNERSHIP_FILE"
}

reset_case absent
cleanup_stale_ppe_deoffload_firewall
[ ! -s "$PPE_TEST_LOG" ] ||
    grep -Fq 'iptables -w -t mangle -S' "$PPE_TEST_LOG"

reset_case exact
write_valid_owner
cleanup_stale_ppe_deoffload_firewall
[ "$(cat "$PPE_TEST_STATE")" = absent ]
[ ! -e "$PPE_DEOFFLOAD_OWNERSHIP_FILE" ]
grep -Fq -- '-D PREROUTING -m comment --comment keen-pbr-sb:ppe:prerouting -j KeenPbrPpe4' "$PPE_TEST_LOG"
grep -Fq -- '-D FORWARD -m comment --comment keen-pbr-sb:ppe:forward -j KeenPbrPpe4' "$PPE_TEST_LOG"
grep -Fq -- '-D KeenPbrPpe4 -p tcp -m tcp -m multiport' "$PPE_TEST_LOG"
grep -Fq -- '-D KeenPbrPpe4 -m comment --comment "keen-pbr-sb:ppe:return" -j RETURN' "$PPE_TEST_LOG"
! grep -Fq -- '-F KeenPbrPpe4' "$PPE_TEST_LOG"
grep -Fq -- '-X KeenPbrPpe4' "$PPE_TEST_LOG"

# A foreign append after the exact snapshot must abort the whole transaction;
# lifecycle cleanup may never flush that concurrent state.
reset_case concurrent-stray
write_valid_owner
if cleanup_stale_ppe_deoffload_firewall; then
    echo "accepted PPE cleanup after a concurrent foreign append" >&2
    exit 1
fi
[ "$(cat "$PPE_TEST_STATE")" = concurrent-stray-mutated ]
[ -e "$PPE_DEOFFLOAD_OWNERSHIP_FILE" ]
! grep -Fq -- '-F KeenPbrPpe4' "$PPE_TEST_LOG"
grep -Fq -- '-X KeenPbrPpe4' "$PPE_TEST_LOG"

reset_case duplicate
cleanup_stale_ppe_deoffload_firewall
[ "$(grep -F -c -- 'stdin: -D PREROUTING ' "$PPE_TEST_LOG")" -eq 2 ]
[ "$(grep -F -c -- 'stdin: -D FORWARD ' "$PPE_TEST_LOG")" -eq 2 ]

for unsafe in foreign foreign-goto malformed noncanonical-ports slot-overflow \
    quic-missing-module \
    noncontiguous-index wrong-rule-order reserved-stray \
    empty-reserved-stray no-chain-reserved-stray quoted-reserved-stray; do
    reset_case "$unsafe"
    if cleanup_stale_ppe_deoffload_firewall; then
        echo "accepted unsafe PPE graph: $unsafe" >&2
        exit 1
    fi
    [ "$(cat "$PPE_TEST_STATE")" = "$unsafe" ]
    ! grep -Fq 'iptables-restore' "$PPE_TEST_LOG"
done

# A verified active marker is durable ownership evidence for the narrow crash
# window where the chain exists but its rules/hooks are absent.
reset_case empty-owned
write_valid_owner
cleanup_stale_ppe_deoffload_firewall
[ "$(cat "$PPE_TEST_STATE")" = absent ]
[ ! -e "$PPE_DEOFFLOAD_OWNERSHIP_FILE" ]

for failed in restore-fail remains; do
    reset_case "$failed"
    write_valid_owner
    if cleanup_stale_ppe_deoffload_firewall; then
        echo "accepted failed PPE cleanup: $failed" >&2
        exit 1
    fi
    [ -e "$PPE_DEOFFLOAD_OWNERSHIP_FILE" ]
done

reset_case absent
printf '%s\n' unexpected > "$PPE_DEOFFLOAD_OWNERSHIP_FILE"
chmod 0600 "$PPE_DEOFFLOAD_OWNERSHIP_FILE"
if cleanup_stale_ppe_deoffload_firewall; then
    echo "accepted invalid PPE ownership marker" >&2
    exit 1
fi
[ -e "$PPE_DEOFFLOAD_OWNERSHIP_FILE" ]

reset_case absent
printf 'iptables\n\n' > "$PPE_DEOFFLOAD_OWNERSHIP_FILE"
chmod 0600 "$PPE_DEOFFLOAD_OWNERSHIP_FILE"
if cleanup_stale_ppe_deoffload_firewall; then
    echo "accepted PPE ownership marker with trailing data" >&2
    exit 1
fi
[ -e "$PPE_DEOFFLOAD_OWNERSHIP_FILE" ]

reset_case absent
printf '%s\n' iptables > "$PPE_DEOFFLOAD_OWNERSHIP_FILE"
chmod 0644 "$PPE_DEOFFLOAD_OWNERSHIP_FILE"
if cleanup_stale_ppe_deoffload_firewall; then
    echo "accepted PPE ownership marker with an unsafe mode" >&2
    exit 1
fi
[ -e "$PPE_DEOFFLOAD_OWNERSHIP_FILE" ]

reset_case absent
rm -rf "$work/bin-no-iptables"
mkdir "$work/bin-no-iptables"
old_path=$PATH
PATH="$work/bin-no-iptables:/bin:/usr/bin"
export PATH
cleanup_stale_ppe_deoffload_firewall
write_valid_owner
if cleanup_stale_ppe_deoffload_firewall; then
    echo "accepted missing iptables with a durable PPE owner" >&2
    exit 1
fi
PATH=$old_path
export PATH

reset_case exact
write_valid_owner
if (pidof() { printf '%s\n' 4242; }
    cleanup_stale_ppe_deoffload_firewall); then
    echo "accepted PPE cleanup while the daemon writer is live" >&2
    exit 1
fi
[ "$(cat "$PPE_TEST_STATE")" = exact ]
[ -e "$PPE_DEOFFLOAD_OWNERSHIP_FILE" ]

echo "Keenetic PPE de-offload cleanup checks passed"

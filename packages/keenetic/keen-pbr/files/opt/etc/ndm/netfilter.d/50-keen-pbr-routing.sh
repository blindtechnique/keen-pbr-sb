#!/opt/bin/sh

case "$type" in
    iptables|ip6tables) ;;
    *) exit 0 ;;
esac

case "$table" in
    mangle)
        refresh_action=reapply-firewall
        ;;
    nat)
        refresh_action=reapply-nat
        ;;
    *)
        exit 0
        ;;
esac

init_script=${KEEN_PBR_INIT_SCRIPT:-/opt/etc/init.d/S80keen-pbr}
logger -t "keen-pbr" \
    "Scheduling $refresh_action after netfilter $table change"
"$init_script" "$refresh_action" >/dev/null 2>&1 || exit 0

if [ -f /opt/etc/keen-pbr/hook.sh ]; then
    keen_pbr_hook="netfilter"
    . /opt/etc/keen-pbr/hook.sh
fi

exit 0

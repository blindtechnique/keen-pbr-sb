#!/bin/sh
# Remove our late TCP hooks before 100-nfqws2.sh recreates the pre-NAT hook.
# 110-keen-pbr-nfqws-tcp.sh reapplies them from the finished vendor rules.
# No vendor-file edits or service/routing control; failure is non-fatal.
case "$table:$type" in
    mangle:iptables|nat:iptables|mangle:ip6tables|nat:ip6tables)
        if [ -x /opt/usr/lib/keen-pbr/nfqws-tcp-window.sh ]; then
            /opt/usr/lib/keen-pbr/nfqws-tcp-window.sh remove "$type" >/dev/null 2>&1 || true
        fi
        ;;
esac
exit 0

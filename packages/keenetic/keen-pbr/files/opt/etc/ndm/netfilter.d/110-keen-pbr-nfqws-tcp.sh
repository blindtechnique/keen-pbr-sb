#!/bin/sh
# Runs after the vendor's 100-nfqws2.sh recreates its chains. No routing reload.
case "$table:$type" in
    mangle:iptables|nat:iptables|mangle:ip6tables|nat:ip6tables)
        if [ -x /opt/usr/lib/keen-pbr/nfqws-tcp-window.sh ]; then
            /opt/usr/lib/keen-pbr/nfqws-tcp-window.sh apply "$type" >/dev/null 2>&1 || true
        fi
        ;;
esac
exit 0

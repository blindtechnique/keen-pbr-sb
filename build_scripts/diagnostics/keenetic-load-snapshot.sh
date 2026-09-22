#!/bin/sh
# Finite, read-only /proc observer. No config writes, packet capture or probes.
# Usage: sh keenetic-load-snapshot.sh [samples: 2..720] [interval: 1..60]
set -eu
PATH=/opt/sbin:/opt/bin:/opt/usr/sbin:/opt/usr/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
samples=${1:-61}
interval=${2:-5}
case "$samples:$interval" in *[!0-9:]*|:*|*:) exit 2 ;; esac
[ "$#" -le 2 ] && [ "$samples" -ge 2 ] && [ "$samples" -le 720 ] &&
    [ "$interval" -ge 1 ] && [ "$interval" -le 60 ] || exit 2
printf 'meta\tformat\tkeenetic-load-v1\n'
printf 'meta\tkernel\t%s\n' "$(uname -sr)"
printf 'meta\tarchitecture\t%s\n' "$(uname -m)"
printf 'meta\tstarted\t%s\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')"
printf 'meta\tsamples\t%s\nmeta\tinterval\t%s\n' "$samples" "$interval"
# Kernel process counters and system counters share units; no assumed CLK_TCK.
awk '/^cpu[0-9]/ {n++} END {printf "meta\tcpus\t%d\n",n}' /proc/stat
printf 'meta\tprocess_memory_unit\tVmRSS_KiB\n'
for path in /proc/sys/net/netfilter/nf_conntrack_fastnat /proc/sys/net/ipv4/netfilter/ip_conntrack_fastnat; do
    [ ! -r "$path" ] || printf 'meta\t%s\t%s\n' "$path" "$(cat "$path")"
done
index=0
while [ "$index" -lt "$samples" ]; do
    read -r uptime rest < /proc/uptime
    printf 'sample\t%s\t%s\n' "$index" "$uptime"
    awk -v t="$uptime" '/^cpu / {printf "cpu\t%s",t; for(i=2;i<=9;i++) printf "\t%s",$i; printf "\n"}' /proc/stat
    awk -v t="$uptime" '/^(MemTotal|MemAvailable|MemFree|Buffers|Cached|SwapTotal|SwapFree|Dirty):/ {sub(/:$/,"",$1); printf "mem\t%s\t%s\t%s\n",t,$1,$2}' /proc/meminfo
    awk -v t="$uptime" '{printf "load\t%s\t%s\t%s\t%s\n",t,$1,$2,$3}' /proc/loadavg
    # One awk handles the snapshot. A process disappearing must not abort all
    # subsequent /proc files (awk file operands alone have that race).
    for path in /proc/[0-9]*/stat; do
        if { IFS= read -r row < "$path"; } 2>/dev/null; then
            pid=${row%% *}
            # Entware can launch sing-box through ld.so: /proc/comm then names
            # the loader. Inspect only the executable token, never print argv.
            case "$row" in
                *' (ld-'*)
                    if tr '\000' '\n' < "/proc/$pid/cmdline" 2>/dev/null |
                        grep -Eq '(^|/)(sing-box|sing-box[-._0-9][^/]*)$'; then
                        printf 'family %s sing-box\n' "$pid"
                    fi
                    ;;
            esac
            printf '%s\n' "$row"
            case "$row" in
                *' (keen-pbr) '*|*' (dnsmasq) '*|*' (transport-manag)'*|*' (nfqws'*|*' (sing-box'*|*' (singbox'*|*' (ld-'*)
                    pid=${row%% *}
                    if [ -r "/proc/$pid/status" ]; then
                        awk -v pid="$pid" '/^VmRSS:/ {print "rss",pid,$2}' "/proc/$pid/status" 2>/dev/null || true
                    fi
                    ;;
            esac
        fi
    done | awk -v t="$uptime" '
        $1=="rss" {rss[$2]=$3; next}
        $1=="family" {override[$2]=$3; next}
        {pid=$1; comm=$0; sub(/^[^(]*\(/,"",comm); sub(/\) .*/,"",comm)
         family=override[pid]
         if(comm=="keen-pbr") family="core"
         else if(comm ~ /^transport-manag/) family="manager"
         else if(comm=="dnsmasq") family="dnsmasq"
         else if(comm ~ /^nfqws/) family="nfqws"
         else if(comm ~ /^(sing-box|singbox)/) family="sing-box"
         if(family!="") {
             fields=$0; sub(/^.*\) /,"",fields); split(fields,a," ")
             details[pid]=family "\t" a[20] "\t" a[12] "\t" a[13]
         }}
        END {for(pid in details) printf "proc\t%s\t%s\t%s\t%s\n",t,pid,details[pid],(pid in rss ? rss[pid] : -1)}'
    if [ -r /proc/net/netfilter/nfnetlink_queue ]; then
        awk -v t="$uptime" '{printf "queue\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",t,$1,$2,$3,$6,$7,$8}' /proc/net/netfilter/nfnetlink_queue
    fi
    awk -v t="$uptime" 'NR>2 {gsub(/:/," "); printf "net\t%s\t%s\t%s\t%s\t%s\t%s\n",t,$1,$2,$3,$10,$11}' /proc/net/dev
    for path in /sys/class/thermal/thermal_zone*/temp; do
        [ ! -r "$path" ] || printf 'temp\t%s\t%s\t%s\n' "$uptime" "$path" "$(cat "$path")"
    done
    printf 'end_sample\t%s\n' "$uptime"
    index=$((index + 1))
    [ "$index" -eq "$samples" ] || sleep "$interval"
done
printf 'complete\t%s\n' "$samples"

#!/bin/sh

action="${ACTION:-${1:-}}"

# fw4 executes type=script includes before it publishes the replacement
# ruleset. That phase must stay passive, otherwise fw4 can erase the repair
# immediately afterwards. The firewall hotplug wrapper sets this marker only
# for the post-reload notification path.
[ "${KEEN_PBR_FIREWALL_POST_RELOAD:-0}" = "1" ] || exit 0

logger -t "keen-pbr" "[firewall.sh] Received action '$action'"

case "$action" in
    ""|includes|reload|restart)
        ;;
    *)
        exit 0
        ;;
esac

init_script=${KEEN_PBR_INIT_SCRIPT:-/etc/init.d/keen-pbr}
if [ -x "$init_script" ] && "$init_script" enabled; then
    logger -t "keen-pbr" "[firewall.sh] Sending SIGUSR1 to keen-pbr due to firewall action: ${action:-fw4-include}"
    "$init_script" reapply_firewall
fi

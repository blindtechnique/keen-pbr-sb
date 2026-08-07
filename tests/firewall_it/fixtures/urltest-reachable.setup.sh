ip netns add "$KPBR_SERVER_NS"
ip netns exec "$KPBR_SERVER_NS" ip link set lo up

ip link add wan_fast netns "$KPBR_CLIENT_NS" type veth peer name srv_fast netns "$KPBR_SERVER_NS"
ip netns exec "$KPBR_CLIENT_NS" ip addr add 10.203.0.2/24 dev wan_fast
ip netns exec "$KPBR_CLIENT_NS" ip link set wan_fast up
ip netns exec "$KPBR_SERVER_NS" ip addr add 10.203.0.1/24 dev srv_fast
ip netns exec "$KPBR_SERVER_NS" ip link set srv_fast up

ip netns exec "$KPBR_CLIENT_NS" ip link add wan_dead type dummy
ip netns exec "$KPBR_CLIENT_NS" ip link set wan_dead up

# The urltest probe gets exactly one attempt with no retry, so it must not be
# allowed to race the server's listening socket. urltest_server.py opens this
# FIFO for writing only after bind()+listen() have returned, so blocking on the
# read end is a happens-before edge rather than a guessed delay. The timeout is
# only a deadlock guard for a server that dies before it can ever signal.
ready_fifo="$(mktemp -u /tmp/keen-pbr-urltest-ready.XXXXXX)"
mkfifo "$ready_fifo"

ip netns exec "$KPBR_SERVER_NS" python3 /opt/keen-pbr/firewall-it/scripts/urltest_server.py --host 10.203.0.1 --port 18080 --ready-fifo "$ready_fifo" &
server_pid="$!"

if ! timeout 30 cat "$ready_fifo" >/dev/null; then
  echo "urltest_server.py never signalled readiness on $ready_fifo" >&2
  rm -f "$ready_fifo"
  exit 1
fi
rm -f "$ready_fifo"

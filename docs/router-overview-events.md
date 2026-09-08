# Event-driven router overview metadata

WAN and hotspot observations keep their independent 60-second TTL and
60-second retry after a failed RCI observation. Local CPU/RAM/traffic metrics
retain their separate lightweight path and existing schedule.

## Event routing

| Observation | Signals that mark it stale |
| --- | --- |
| WAN/internet/address | Main-table default-route changes, interface addresses, administrative/link topology changes, monitor gap or reconnect |
| Hotspot client totals/activity | Meaningful IPv4/IPv6 neighbor changes, administrative/link topology changes, monitor gap or reconnect |
| Model/firmware | None of these signals; its existing shared version cache is unchanged |

The existing netlink monitor subscribes to neighbor messages only in API builds.
This subscription is optional: unsupported kernels retain link/address/route
monitoring and the ordinary metadata TTL fallback. A bounded 2048-entry tracker
coalesces neighbor identity/presence/failure changes and ignores routine
REACHABLE/STALE/DELAY/PROBE transitions. It does not count clients: hotspot RCI
remains the source of the displayed totals. Overflow evicts old hints; there is
no disk history or unbounded neighbor inventory.

Neighbor-only events return before conntrack teardown, interface reconciliation,
VPN probes, routing epochs or firewall work. Other events retain their previous
routing behavior. Overview/SSE delivery is best effort and cannot interrupt the
normal routing event or reconnect recovery.

## Reads and browser delivery

Invalidation only sets a pending bit; it never performs RCI work in the daemon
event loop, erases the last good value or starts a new background worker. The
next API read refreshes only affected expired/dirty observations. Events during
an in-flight fetch remain pending. An event refresh is limited to once per
five seconds after a completed attempt and does not bypass failure retry.

The existing status SSE stream carries a data-free `router_info` change event.
The WebUI coalesces events in a fixed five-second window and refreshes only the
active `system-router` query. If an older GET is still running, it finishes
normally and a single successor waits five seconds from its completion; a burst
cannot keep cancelling requests or postpone refresh indefinitely. Reconnecting
the stream schedules the same targeted read. Closing the session cancels pending
event work. No extra polling or EventSource is added; fallback metadata polling
stays at 60 seconds and lightweight local metrics stay at 15 seconds.

This makes event-visible changes available without waiting for the full TTL;
it is not a fixed five-second end-to-end SLA. RCI latency, an in-flight request
or error retry can delay delivery. Registration/name-only changes and Wi-Fi
association without a relevant IP neighbor transition still use the TTL fallback.

## Кратко по-русски

Данные WAN и клиентов обновляются адресно по событиям, без нового постоянного
опроса. Счётчик клиентов остаётся из Keenetic hotspot, а ARP/NDP служит только
сигналом перечитать его. Повторы объединяются; изменения во время запроса не
теряются. При ошибке сохраняются последние корректные данные и прежний интервал
повторной попытки. Маршрутизация, VPN, nfqws и sing-box из-за клиентских событий
не перезапускаются. Для изменений без событий остаётся минутное обновление.

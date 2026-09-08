# Background task diagnostics

`GET /api/diagnostics/tasks` extends the existing bounded, pull-only registry.
It does not schedule work, authorize mutations, change retry policies, or join
the runtime inventory/SSE stream. The UI lives in Settings → Logging →
Background tasks; opening the details or selecting Refresh requests one snapshot.
There is no polling, automatic retry, or dashboard card.

## Failure streak

`consecutive_failures` counts terminal failures in publication order under the
existing metrics mutex. Success and noop reset it; skipped and abandoned attempts
preserve it. Starting a run does not reset the streak. It remains meaningful after
lifetime aggregate counters saturate, and itself saturates at the registry ceiling.
All counters are process-local, not persistent incident history.

## Next scheduled callback

`scheduling_state` is `scheduled`, `not_scheduled`, or `unknown`.
`next_run_at_unix_ms` is present only for a known scheduled callback. Existing
kernel `CLOCK_MONOTONIC` timer deadlines are projected onto the snapshot wall clock;
the UI displays an absolute time in the browser time zone, not a live countdown.

The Scheduler matches exact timer labels under its existing entries mutex. It
calls `timerfd_gettime` and non-blocking `poll`, without reading expirations,
calling callbacks, or rearming timers. An unread expiration is due now, even if
a repeating timer already has a future next tick. The earliest matching alias
wins. An inspection error yields unknown for that family, without losing metrics
for the other tasks. No timer/disarmed timer means not scheduled, **not disabled**.

| Metric | Existing timer labels |
| --- | --- |
| `resolver-hash-refresh` | `resolver-config-hash-actual`, `resolver-config-hash-actual-retry`, `resolver-config-hash-inflight-retry`, `resolver-config-hash-executor-retry`, `resolver-config-hash-stale-generation-retry` |
| `keenetic-dns-refresh` | `keenetic-dns-refresh`, `keenetic-dns-refresh-admission-retry` |
| `owned-snat-health` | `owned-snat-health` |
| `interface-probe` | `interface-probe` |
| `interface-traffic-sample` | `interface-traffic-sample` |

This is the next planned callback, not guaranteed work or automatic recovery.
For example, the traffic timer ticks every two seconds, while counter reads are
viewer-dependent and may happen less often. Queued/trailing work and already
acknowledged timer callbacks may have no timer deadline; `in_flight` is displayed
separately. Metrics and timers are observations, not one atomic execution snapshot.
No timing, lock admission, routing, or service lifecycle behavior is changed.

## Compatibility and validation

All three new API fields are optional. Older server responses show No data for
missing values, not invented zeros/deadlines. Known task labels and outcomes have
Russian/English labels; technical details remain expandable. Closing the section
aborts its request and ignores late results; reopening makes a fresh request.

The focused `keen-pbr-background-task-diagnostics-tests` target covers the real
timerfd with the existing test fd registrar, registry outcomes, wire projection,
and absence from SSE. It does not run the HTTP/authentication stack; the existing
HTTP endpoint test remains in `keen-pbr-tests`. Local checks do not replace
Keenetic package/router acceptance.

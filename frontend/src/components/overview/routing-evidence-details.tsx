import { useTranslation } from "react-i18next"
import type { TFunction } from "i18next"
import { Loader2 } from "lucide-react"

import type {
  ConfigObject,
  RoutingTestFirewallCounters,
  RoutingTestHttpProbe,
  RoutingTestResponse,
} from "@/api/generated/model"
import { getListReferenceLabel } from "@/lib/list-display"
import { getRouteRuleDisplayName } from "@/pages/routing-rules-utils"
import { Button } from "@/components/ui/button"
import type { RoutingHttpProbeControls } from "./routing-http-probe-state"

import { formatRoutingFwmark } from "./routing-diagnostics-utils"
import {
  formatEvidenceTime,
  getConnectionEvidence,
  sameRoutingEvidenceAddress,
} from "./routing-evidence-model"

export function RoutingEvidenceDetails({
  diagnostics,
  lists,
  ...httpControls
}: {
  diagnostics: RoutingTestResponse
  lists?: ConfigObject["lists"]
} & RoutingHttpProbeControls) {
  const { t } = useTranslation()
  const unknown = t("overview.routingDiagnostics.statusUnknown")
  const snapshot = diagnostics.connections
  const ruleName = (index: number | undefined) => {
    if (index == null || !Number.isInteger(index) || index < 0) return unknown
    const rule = diagnostics.rule_diagnostics.find(
      (item) => item.rule_index === index
    )
    return rule ? getRouteRuleDisplayName(rule.rule, index) : `#${index + 1}`
  }
  const dnsSource = !diagnostics.is_domain
    ? t("overview.routingDiagnostics.evidence.dnsLiteral")
    : diagnostics.dns_source === "configured_resolver"
      ? t("overview.routingDiagnostics.evidence.dnsConfigured")
      : diagnostics.dns_source === "system_resolver"
        ? t("overview.routingDiagnostics.evidence.dnsSystem")
        : t("overview.routingDiagnostics.evidence.dnsUnknown")

  return (
    <details className="rounded-md border p-3 text-sm">
      <summary className="cursor-pointer font-medium">
        {t("overview.routingDiagnostics.evidence.title")}
      </summary>
      <div className="mt-3 space-y-4">
        <p className="text-muted-foreground">
          {t("overview.routingDiagnostics.evidence.scope")}
        </p>
        <div className="space-y-1">
          <h4 className="font-medium">
            {t("overview.routingDiagnostics.evidence.dns")}
          </h4>
          <p>
            {dnsSource}
            {diagnostics.is_domain && diagnostics.dns_server ? (
              <>
                : <code>{diagnostics.dns_server}</code>
              </>
            ) : null}
          </p>
          {diagnostics.is_domain ? (
            <>
              <p className="font-mono break-all">
                {diagnostics.resolved_ips.join(", ") || unknown}
              </p>
              <p className="text-muted-foreground">
                {t("overview.routingDiagnostics.evidence.dnsScope")}
              </p>
            </>
          ) : null}
        </div>
        <p className="text-muted-foreground">
          {snapshot?.snapshot_available
            ? t("overview.routingDiagnostics.evidence.snapshot", {
                time: formatEvidenceTime(snapshot.snapshot_at) ?? unknown,
                count: snapshot.items.length,
                total: snapshot.total,
              })
            : t("overview.routingDiagnostics.evidence.snapshotUnavailable")}
          {snapshot?.truncated ? (
            <> {t("overview.routingDiagnostics.evidence.truncated")}</>
          ) : null}
        </p>
        {diagnostics.results.map((entry) => {
          const kernel = entry.kernel_route
          const connections = getConnectionEvidence(diagnostics, entry)
          const kernelStatus =
            kernel?.route_status === "resolved"
              ? t("overview.routingDiagnostics.evidence.fibResolved")
              : kernel?.route_status === "unroutable"
                ? t("overview.routingDiagnostics.evidence.fibUnroutable")
                : kernel?.route_status === "not_applicable"
                  ? t("overview.routingDiagnostics.evidence.fibNotApplicable")
                  : t("overview.routingDiagnostics.evidence.fibUnknown")
          return (
            <section key={entry.ip} className="space-y-2 border-t pt-3">
              <h4 className="font-mono font-medium break-all">{entry.ip}</h4>
              <dl className="space-y-3">
                <div>
                  <dt className="font-medium">
                    {t("overview.routingDiagnostics.evidence.listRule")}
                  </dt>
                  <dd className="break-words">
                    {entry.list_match
                      ? t("overview.routingDiagnostics.listMatch", {
                          list: getListReferenceLabel(
                            entry.list_match.list,
                            lists
                          ),
                          via: entry.list_match.via,
                        })
                      : t("overview.routingDiagnostics.evidence.noList")}
                    <p>
                      {t("overview.routingDiagnostics.evidence.expectedRule", {
                        rule: ruleName(entry.expected_rule_index),
                      })}
                    </p>
                    {entry.evaluation === "insufficient_context" ? (
                      <p>
                        {t("overview.routingDiagnostics.packetContextRequired")}
                      </p>
                    ) : null}
                  </dd>
                </div>
                <div>
                  <dt className="font-medium">
                    {t("overview.routingDiagnostics.evidence.mark")}
                  </dt>
                  <dd>
                    <p>
                      {t("overview.routingDiagnostics.evidence.markValue", {
                        mark: formatRoutingFwmark(kernel?.fwmark) ?? unknown,
                        mask:
                          formatRoutingFwmark(diagnostics.fwmark_mask) ??
                          unknown,
                      })}
                    </p>
                    <p>
                      {t("overview.routingDiagnostics.evidence.actualRule", {
                        rule: ruleName(entry.actual_rule_index),
                      })}
                    </p>
                    <FirewallCounterEvidence
                      counters={entry.firewall_counters}
                    />
                  </dd>
                </div>
                <PolicyRuleEvidence entry={entry} />
                <div>
                  <dt className="font-medium">
                    {t("overview.routingDiagnostics.evidence.fib")}
                  </dt>
                  <dd>
                    <p>{kernelStatus}</p>
                    <p>
                      {t("overview.routingDiagnostics.evidence.fibDetails", {
                        interface: kernel?.interface || unknown,
                        table: kernel?.table ?? unknown,
                      })}
                    </p>
                    {kernel?.detail ? (
                      <pre className="text-xs break-all whitespace-pre-wrap text-muted-foreground">
                        {kernel.detail}
                      </pre>
                    ) : null}
                  </dd>
                </div>
                <div>
                  <dt className="font-medium">
                    {t("overview.routingDiagnostics.evidence.connections")}
                  </dt>
                  <dd className="space-y-2">
                    {!snapshot?.snapshot_available ? (
                      <p>
                        {t(
                          "overview.routingDiagnostics.evidence.snapshotUnavailable"
                        )}
                      </p>
                    ) : connections.length === 0 ? (
                      <p>
                        {t(
                          "overview.routingDiagnostics.evidence.noConnections"
                        )}
                      </p>
                    ) : (
                      connections.map(({ connection, mark }, index) => (
                        <div
                          key={index}
                          className="space-y-1 rounded bg-muted/40 p-2"
                        >
                          <p>
                            {mark === "matching"
                              ? t(
                                  "overview.routingDiagnostics.evidence.markMatching"
                                )
                              : mark === "different"
                                ? t(
                                    "overview.routingDiagnostics.evidence.markDifferent"
                                  )
                                : t(
                                    "overview.routingDiagnostics.evidence.markUnconfirmed"
                                  )}
                          </p>
                          <p className="font-mono text-xs break-all">
                            {connection.protocol} {connection.state || "—"}
                            {" · "}[{connection.source}]:
                            {connection.source_port}
                            {" → "}[{connection.destination}]:
                            {connection.destination_port}
                          </p>
                          <p className="font-mono text-xs">
                            {t(
                              "overview.routingDiagnostics.evidence.connectionMark",
                              {
                                mark:
                                  formatRoutingFwmark(connection.mark) ??
                                  unknown,
                              }
                            )}
                          </p>
                          <p className="text-xs">
                            {t(
                              "overview.routingDiagnostics.evidence.lastSeen",
                              {
                                time:
                                  formatEvidenceTime(connection.last_seen) ??
                                  unknown,
                              }
                            )}
                          </p>
                        </div>
                      ))
                    )}
                  </dd>
                </div>
                <HttpProbeEvidence ip={entry.ip} {...httpControls} />
              </dl>
            </section>
          )
        })}
      </div>
    </details>
  )
}

function HttpProbeEvidence({
  ip,
  onHttpProbe,
  httpProbe,
  httpPendingIp,
  httpError,
}: { ip: string } & RoutingHttpProbeControls) {
  const { t } = useTranslation()
  const probe =
    httpProbe && sameRoutingEvidenceAddress(httpProbe.ip, ip)
      ? httpProbe
      : undefined
  const pending = httpPendingIp === ip
  const failed = httpError?.ip === ip
  const unknown = t("overview.routingDiagnostics.statusUnknown")
  if (!onHttpProbe && !probe && !pending && !failed) return null
  return (
    <div>
      <dt className="font-medium">
        {t("overview.routingDiagnostics.evidence.httpTitle")}
      </dt>
      <dd className="space-y-2">
        <p className="text-muted-foreground">
          {t("overview.routingDiagnostics.evidence.httpScope")}
        </p>
        {onHttpProbe ? (
          <Button
            type="button"
            variant="outline"
            className="h-auto min-h-8 max-w-full text-left whitespace-normal"
            disabled={httpPendingIp != null}
            onClick={() => onHttpProbe(ip)}
          >
            {pending ? (
              <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
            ) : null}
            {t("overview.routingDiagnostics.evidence.httpCheck")}
          </Button>
        ) : null}
        <div aria-live="polite" className="space-y-2">
          {pending ? (
            <p role="status">
              {t("overview.routingDiagnostics.evidence.httpPending")}
            </p>
          ) : null}
          {failed ? (
            <p role="status">
              {t("overview.routingDiagnostics.evidence.httpRequestFailed")}
            </p>
          ) : null}
          {probe && !pending ? (
            <>
              <p className="font-medium">
                {probe.status === "answered"
                  ? t("overview.routingDiagnostics.evidence.httpAnswered")
                  : probe.status === "not_applicable"
                    ? t("overview.routingDiagnostics.evidence.httpNotAttempted")
                    : probe.status === "unavailable"
                      ? t(
                          "overview.routingDiagnostics.evidence.httpUnavailable"
                        )
                      : t(
                          "overview.routingDiagnostics.evidence.httpIncomplete"
                        )}
                {probe.http_status != null
                  ? ` · HTTP ${probe.http_status}`
                  : null}
              </p>
              <p>{httpProbeReason(probe.reason, t)}</p>
              <p className="text-muted-foreground">
                {t("overview.routingDiagnostics.evidence.httpFresh")}
              </p>
              {probe.url ? (
                <p className="font-mono text-xs break-all">
                  {probe.method} {probe.url}
                </p>
              ) : null}
              <p>
                {t("overview.routingDiagnostics.evidence.httpRoute", {
                  ip: probe.ip,
                  interface: probe.interface || unknown,
                  mark: formatRoutingFwmark(probe.fwmark) ?? unknown,
                  table: probe.table ?? unknown,
                })}
              </p>
              {probe.connected_ip ? (
                <p>
                  {t("overview.routingDiagnostics.evidence.httpConnectedIp", {
                    ip: probe.connected_ip,
                  })}
                </p>
              ) : null}
              <p>
                {probe.attempted_at > 0
                  ? t("overview.routingDiagnostics.evidence.httpAttemptedAt", {
                      time: formatEvidenceTime(probe.attempted_at) ?? unknown,
                    })
                  : t("overview.routingDiagnostics.evidence.httpNotAttempted")}
              </p>
              {probe.elapsed_ms != null ? (
                <p>
                  {t("overview.routingDiagnostics.evidence.httpElapsed", {
                    time: probe.elapsed_ms,
                  })}
                </p>
              ) : null}
              {probe.connect_ms != null ? (
                <p>
                  {t("overview.routingDiagnostics.evidence.httpConnect", {
                    time: probe.connect_ms,
                  })}
                </p>
              ) : null}
              {probe.tls_ms != null ? (
                <p>
                  {t("overview.routingDiagnostics.evidence.httpTls", {
                    time: probe.tls_ms,
                  })}
                </p>
              ) : null}
            </>
          ) : null}
        </div>
      </dd>
    </div>
  )
}

function httpProbeReason(
  reason: RoutingTestHttpProbe["reason"],
  t: TFunction
): string {
  switch (reason) {
    case "http_response":
      return t("overview.routingDiagnostics.evidence.httpResponse")
    case "context_required":
      return t("overview.routingDiagnostics.evidence.httpContextRequired")
    case "no_route":
      return t("overview.routingDiagnostics.evidence.httpNoRoute")
    case "destination_changed":
      return t("overview.routingDiagnostics.evidence.httpDestinationChanged")
    case "blocked_route":
      return t("overview.routingDiagnostics.evidence.httpBlockedRoute")
    case "binding_failed":
      return t("overview.routingDiagnostics.evidence.httpBindingFailed")
    case "tls_error":
      return t("overview.routingDiagnostics.evidence.httpTlsError")
    case "timeout":
      return t("overview.routingDiagnostics.evidence.httpTimeout")
    case "connection_failed":
      return t("overview.routingDiagnostics.evidence.httpConnectionFailed")
    case "unsupported_target":
      return t("overview.routingDiagnostics.evidence.httpUnsupportedTarget")
    case "transport_error":
      return t("overview.routingDiagnostics.evidence.httpTransportError")
    case "budget_exhausted":
      return t("overview.routingDiagnostics.evidence.httpBudgetExhausted")
    case "response_limit":
      return t("overview.routingDiagnostics.evidence.httpResponseLimit")
    default:
      return t("overview.routingDiagnostics.evidence.httpUnavailable")
  }
}

function FirewallCounterEvidence({
  counters,
}: {
  counters?: RoutingTestFirewallCounters
}) {
  const { t } = useTranslation()
  const unknown = t("overview.routingDiagnostics.statusUnknown")

  return (
    <div className="mt-2 space-y-2">
      <p className="font-medium">
        {t("overview.routingDiagnostics.evidence.counterTitle")}
      </p>
      {counters?.status !== "observed" ? (
        <p>
          {counters?.status === "ambiguous"
            ? t("overview.routingDiagnostics.evidence.counterAmbiguous")
            : counters?.status === "unavailable"
              ? t("overview.routingDiagnostics.evidence.counterUnavailable")
              : counters?.status === "not_applicable"
                ? t("overview.routingDiagnostics.evidence.counterNotApplicable")
                : t("overview.routingDiagnostics.evidence.counterMissing")}
        </p>
      ) : (
        <>
          <p className="text-muted-foreground">
            {t("overview.routingDiagnostics.evidence.counterScope")}
          </p>
          <p className="text-muted-foreground">
            {t("overview.routingDiagnostics.evidence.counterSnapshot", {
              time: formatEvidenceTime(counters.snapshot_at) ?? unknown,
              count: counters.rules.length,
              total: counters.total,
            })}
            {counters.truncated ? (
              <> {t("overview.routingDiagnostics.evidence.counterTruncated")}</>
            ) : null}
          </p>
          {counters.rules.length === 0 ? (
            <p>{t("overview.routingDiagnostics.evidence.counterEmpty")}</p>
          ) : (
            counters.rules.map((rule, index) => (
              <div key={index} className="space-y-1 rounded bg-muted/40 p-2">
                <p className="break-all">
                  {t("overview.routingDiagnostics.evidence.counterRule", {
                    family:
                      rule.family === "ipv4"
                        ? "IPv4"
                        : rule.family === "ipv6"
                          ? "IPv6"
                          : unknown,
                    table: rule.table,
                    chain: rule.chain,
                    position: rule.position,
                  })}
                </p>
                <p>
                  {rule.action === "mark"
                    ? t(
                        "overview.routingDiagnostics.evidence.counterMarkAction"
                      )
                    : rule.action === "drop"
                      ? t(
                          "overview.routingDiagnostics.evidence.counterDropAction"
                        )
                      : rule.action === "pass"
                        ? t(
                            "overview.routingDiagnostics.evidence.counterPassAction"
                          )
                        : unknown}
                </p>
                <p className="font-mono text-xs break-all">
                  {t("overview.routingDiagnostics.evidence.counterSet", {
                    set: rule.set_name || "—",
                  })}
                </p>
                {rule.action === "mark" ||
                rule.fwmark != null ||
                rule.fwmask != null ? (
                  <p className="font-mono text-xs">
                    {t("overview.routingDiagnostics.evidence.counterMark", {
                      mark: formatRoutingFwmark(rule.fwmark) ?? unknown,
                      mask: formatRoutingFwmark(rule.fwmask) ?? unknown,
                    })}
                  </p>
                ) : null}
                <p className="font-mono break-all">
                  {t("overview.routingDiagnostics.evidence.counterTotals", {
                    // Keep the wire's exact uint64 decimal strings. These are
                    // absolute per-row values, not sums, deltas or byte rates.
                    packets: rule.packets,
                    bytes: rule.bytes,
                  })}
                </p>
              </div>
            ))
          )}
        </>
      )}
    </div>
  )
}

function PolicyRuleEvidence({
  entry,
}: {
  entry: RoutingTestResponse["results"][number]
}) {
  const { t } = useTranslation()
  const unknown = t("overview.routingDiagnostics.statusUnknown")
  const policy = entry.policy_rules
  const observed = policy?.status === "observed"

  return (
    <div>
      <dt className="font-medium">
        {t("overview.routingDiagnostics.evidence.policy")}
      </dt>
      <dd className="space-y-2">
        <p className="text-muted-foreground">
          {t("overview.routingDiagnostics.evidence.policyScope")}
        </p>
        {!observed ? (
          <p>
            {policy?.status === "not_applicable"
              ? t("overview.routingDiagnostics.evidence.policyNotApplicable")
              : policy?.status === "unavailable"
                ? t("overview.routingDiagnostics.evidence.policyUnavailable")
                : t("overview.routingDiagnostics.evidence.policyMissing")}
          </p>
        ) : (
          <>
            <p className="text-muted-foreground">
              {t("overview.routingDiagnostics.evidence.policySnapshot", {
                time: formatEvidenceTime(policy.snapshot_at) ?? unknown,
                count: policy.rules.length,
                total: policy.total,
              })}
              {policy.truncated ? (
                <>
                  {" "}
                  {t("overview.routingDiagnostics.evidence.policyTruncated")}
                </>
              ) : null}
            </p>
            {policy.rules.length === 0 ? (
              <p>{t("overview.routingDiagnostics.evidence.policyEmpty")}</p>
            ) : (
              // Backend selects compatible complete rules using the full mark,
              // not the owned conntrack mask. A zero rule mask accepts any mark.
              // Incomplete candidates and snapshot order never prove a winner.
              policy.rules.map((rule, index) => (
                <div key={index} className="space-y-1 rounded bg-muted/40 p-2">
                  <p>
                    {t("overview.routingDiagnostics.evidence.policyRule", {
                      family:
                        rule.family === "ipv4"
                          ? "IPv4"
                          : rule.family === "ipv6"
                            ? "IPv6"
                            : unknown,
                      priority: rule.priority,
                      table: rule.table,
                    })}
                  </p>
                  <p className="font-mono text-xs">
                    {t("overview.routingDiagnostics.evidence.policyMark", {
                      mark: formatRoutingFwmark(rule.fwmark) ?? unknown,
                      mask: formatRoutingFwmark(rule.fwmask) ?? unknown,
                    })}
                  </p>
                  <p>
                    {rule.details_complete === true
                      ? t(
                          "overview.routingDiagnostics.evidence.policyMarkMatching"
                        )
                      : t(
                          "overview.routingDiagnostics.evidence.policyIncomplete"
                        )}
                  </p>
                </div>
              ))
            )}
          </>
        )}
      </dd>
    </div>
  )
}

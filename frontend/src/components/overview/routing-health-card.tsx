import { type ReactNode, useMemo, useState } from "react"
import { CheckCircle2 } from "lucide-react"
import { useTranslation } from "react-i18next"

import { ListPlaceholder } from "@/components/shared/list-placeholder"

import type {
  PpeDeoffloadCounter,
  PpeDeoffloadHealth,
  RouteTableCheck,
  RoutingHealthResponse,
} from "@/api/generated/model"
import {
  formatPpePorts,
  getPpeDeoffloadPresentation,
} from "@/components/overview/ppe-deoffload-status-model"
import { Badge } from "@/components/ui/badge"
import { Checkbox } from "@/components/ui/checkbox"

type StatusTone = "healthy" | "warning" | "degraded"

export function RoutingHealthCard({
  routingHealth,
}: {
  routingHealth: RoutingHealthResponse
}) {
  const { t } = useTranslation()
  const [showHealthyEntries, setShowHealthyEntries] = useState(false)

  const firewallRules = useMemo(
    () =>
      filterByHealth(routingHealth.firewall_rules ?? [], showHealthyEntries),
    [routingHealth.firewall_rules, showHealthyEntries]
  )
  const routeTables = useMemo(
    () => filterByHealth(routingHealth.route_tables ?? [], showHealthyEntries),
    [routingHealth.route_tables, showHealthyEntries]
  )
  const policyRules = useMemo(
    () => filterByHealth(routingHealth.policy_rules ?? [], showHealthyEntries),
    [routingHealth.policy_rules, showHealthyEntries]
  )

  const groupedRoutes = useMemo(
    () => groupRouteTables(routeTables),
    [routeTables]
  )
  const hasVisibleEntries =
    Boolean(routingHealth.ppe_deoffload) ||
    firewallRules.length > 0 ||
    groupedRoutes.length > 0 ||
    policyRules.length > 0

  return (
    <div className="flex flex-1 flex-col space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <StatusBadge tone={mapCheckTone(routingHealth.overall)}>
          {routingHealth.overall}
        </StatusBadge>
        <Badge size="xs" variant="outline">
          {routingHealth.firewall_backend}
        </Badge>
        <ChainStateBadge isHealthy={routingHealth.firewall.chain_present}>
          {t("overview.routing.chain")}
        </ChainStateBadge>
        <ChainStateBadge
          isHealthy={routingHealth.firewall.prerouting_hook_present}
        >
          {t("overview.routing.prerouting")}
        </ChainStateBadge>
        <label className="ml-auto flex items-center gap-2 text-xs text-muted-foreground">
          <Checkbox
            checked={showHealthyEntries}
            onCheckedChange={(checked) =>
              setShowHealthyEntries(checked === true)
            }
          />
          <span>{t("overview.routing.showHealthyEntries")}</span>
        </label>
      </div>

      {routingHealth.ppe_deoffload ? (
        <PpeDeoffloadStatus health={routingHealth.ppe_deoffload} />
      ) : null}

      {!hasVisibleEntries && !showHealthyEntries ? (
        <div className="flex min-h-12 items-center gap-2 border-y border-border py-2 text-sm text-success">
          <CheckCircle2 className="size-5 shrink-0" />
          <span>{t("overview.routing.allHealthyDescription")}</span>
        </div>
      ) : null}

      {!hasVisibleEntries && showHealthyEntries ? (
        <ListPlaceholder
          className="min-h-0 flex-1 px-4 py-5"
          description={t("overview.routing.noChecksDescription")}
          title={t("overview.routing.noChecksTitle")}
        />
      ) : null}

      {firewallRules.length > 0 ? (
        <CompactSection
          title={t("overview.routing.sections.firewall")}
          items={firewallRules}
          renderItem={(rule, index) => (
            <CompactDiagnosticRow
              key={`${rule.set_name}-${index}`}
              primary={
                <>
                  <span className="font-mono text-[12px] sm:text-sm">
                    {rule.set_name}
                  </span>
                  <InlineMeta>{rule.action}</InlineMeta>
                  {renderFirewallMark(
                    rule.expected_fwmark,
                    rule.actual_fwmark,
                    t
                  )}
                  {renderInlineDetail(
                    getDiagnosticDetail(rule.status, rule.detail)
                  )}
                </>
              }
              status={rule.status}
            />
          )}
        />
      ) : null}

      {groupedRoutes.length > 0 ? (
        <CompactSection
          title={t("overview.routing.sections.routes")}
          items={groupedRoutes}
          renderItem={(group) => (
            <div className="space-y-1.5" key={group.key}>
              {group.items.map((table, index) => (
                <CompactDiagnosticRow
                  key={`${group.key}-${index}`}
                  primary={
                    <>
                      <span className="text-sm font-medium">
                        {group.outboundTag}
                      </span>
                      <InlineMeta>
                        {t("overview.routing.tableLabel", {
                          value: group.tableId,
                        })}
                      </InlineMeta>
                      <InlineMeta>
                        {table.expected_destination ??
                          t("overview.routing.defaultRoute")}
                      </InlineMeta>
                      <InlineMeta>
                        {formatRouteExpectation(table, t)}
                      </InlineMeta>
                      {renderInlineDetail(getRouteMismatchDetail(table, t))}
                    </>
                  }
                  status={table.status}
                />
              ))}
            </div>
          )}
        />
      ) : null}

      {policyRules.length > 0 ? (
        <CompactSection
          title={t("overview.routing.sections.policies")}
          items={policyRules}
          renderItem={(policy, index) => (
            <CompactDiagnosticRow
              key={`${policy.fwmark}-${policy.expected_table}-${index}`}
              primary={
                <>
                  <span className="font-mono text-[12px] sm:text-sm">
                    {policy.fwmark}/{policy.fwmask}
                  </span>
                  <InlineMeta>
                    {t("overview.routing.tableLabel", {
                      value: policy.expected_table,
                    })}
                  </InlineMeta>
                  <InlineMeta>
                    {t("overview.routing.priorityLabel", {
                      value: policy.priority,
                    })}
                  </InlineMeta>
                  <PresenceBadge
                    label={t("overview.routing.ipv4")}
                    present={policy.rule_present_v4}
                    yesLabel={t("overview.routing.yes")}
                    noLabel={t("overview.routing.no")}
                  />
                  <PresenceBadge
                    label={t("overview.routing.ipv6")}
                    present={policy.rule_present_v6}
                    yesLabel={t("overview.routing.yes")}
                    noLabel={t("overview.routing.no")}
                  />
                  {renderInlineDetail(
                    getDiagnosticDetail(policy.status, policy.detail)
                  )}
                </>
              }
              status={policy.status}
            />
          )}
        />
      ) : null}
    </div>
  )
}

function PpeDeoffloadStatus({ health }: { health: PpeDeoffloadHealth }) {
  const { t } = useTranslation()
  const presentation = getPpeDeoffloadPresentation(health)
  const stateLabel =
    presentation.kind === "verifiedActive"
      ? t("overview.routing.ppe.states.verifiedActive")
      : presentation.kind === "admissibleOnly"
        ? t("overview.routing.ppe.states.admissibleOnly")
        : presentation.kind === "degraded"
          ? t("overview.routing.ppe.states.degraded")
          : presentation.kind === "inactive"
            ? t("overview.routing.ppe.states.inactive")
            : presentation.kind === "off"
              ? t("overview.routing.ppe.states.off")
              : t("overview.routing.ppe.states.unknown")
  const capabilityLabel =
    health.capability === "supported"
      ? t("overview.routing.ppe.capabilities.supported")
      : health.capability === "unsupported"
        ? t("overview.routing.ppe.capabilities.unsupported")
        : t("overview.routing.ppe.capabilities.unknown")
  const modeLabel =
    health.mode === "auto"
      ? t("overview.routing.ppe.modes.auto")
      : t("overview.routing.ppe.modes.off")
  const tcpState = health.tcp.active
    ? t("overview.routing.ppe.protocolStates.active")
    : t("overview.routing.ppe.protocolStates.inactive")
  const quicState = health.quic.active
    ? t("overview.routing.ppe.protocolStates.active")
    : t("overview.routing.ppe.protocolStates.inactive")
  const noPorts = t("overview.routing.ppe.noPorts")
  const tcpDesired = formatPpePorts(health.tcp.desired_ports) ?? noPorts
  const tcpApplied = formatPpePorts(health.tcp.applied_ports) ?? noPorts
  const quicDesired = formatPpePorts(health.quic.desired_ports) ?? noPorts
  const quicApplied = formatPpePorts(health.quic.applied_ports) ?? noPorts
  const lastReconcile = formatPpeTimestamp(health.last_reconcile_ts)
  const observedAt = formatPpeTimestamp(health.observed_at)
  const diagnosticDetail = health.detail ?? health.reason

  return (
    <section className="space-y-2">
      <h3 className="text-sm font-semibold">
        {t("overview.routing.ppe.title")}
      </h3>
      <div className="rounded-md border border-border/70 bg-muted/20 px-3 py-2">
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
          <Badge size="xs" variant={presentation.badgeVariant}>
            {stateLabel}
          </Badge>
          <InlineMeta>
            {t("overview.routing.ppe.capability", {
              value: capabilityLabel,
            })}
          </InlineMeta>
          <InlineMeta>
            {t("overview.routing.ppe.mode", { value: modeLabel })}
          </InlineMeta>
          {health.connskip_packets ? (
            <InlineMeta>
              {t("overview.routing.ppe.connskipWindow", {
                count: health.connskip_packets,
              })}
            </InlineMeta>
          ) : null}
          <InlineMeta>
            {t("overview.routing.ppe.protocolPorts", {
              protocol: "TCP",
              state: tcpState,
              desired: tcpDesired,
              applied: tcpApplied,
            })}
          </InlineMeta>
          <InlineMeta>
            {t("overview.routing.ppe.protocolPorts", {
              protocol: "QUIC",
              state: quicState,
              desired: quicDesired,
              applied: quicApplied,
            })}
          </InlineMeta>
          {formatPpeCounter("PREROUTING", health.prerouting, t)}
          {formatPpeCounter("FORWARD", health.forward, t)}
          {lastReconcile ? (
            <InlineMeta>
              {t("overview.routing.ppe.lastReconcile", {
                value: lastReconcile,
              })}
            </InlineMeta>
          ) : null}
          {observedAt ? (
            <InlineMeta>
              {t("overview.routing.ppe.observedAt", { value: observedAt })}
            </InlineMeta>
          ) : null}
          {diagnosticDetail ? (
            <span className="basis-full text-xs text-muted-foreground">
              {diagnosticDetail}
            </span>
          ) : null}
          {health.prerouting || health.forward ? (
            <span className="basis-full text-xs text-muted-foreground">
              {t("overview.routing.ppe.counterCaveat")}
            </span>
          ) : null}
        </div>
      </div>
    </section>
  )
}

function formatPpeCounter(
  chain: string,
  counter: PpeDeoffloadCounter | undefined,
  t: ReturnType<typeof useTranslation>["t"]
) {
  if (!counter) return null

  return (
    <InlineMeta>
      {t("overview.routing.ppe.rawCounter", {
        chain,
        packets: counter.packets ?? "—",
        bytes: counter.bytes ?? "—",
      })}
    </InlineMeta>
  )
}

function formatPpeTimestamp(value: number | undefined) {
  if (!value || !Number.isFinite(value)) return null

  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "short",
    timeStyle: "medium",
  }).format(new Date(value * 1000))
}

function CompactSection<T>({
  title,
  items,
  renderItem,
}: {
  title: string
  items: T[]
  renderItem: (item: T, index: number) => ReactNode
}) {
  return (
    <section className="space-y-2">
      <div className="flex items-center justify-between gap-2">
        <h3 className="text-sm font-semibold">{title}</h3>
        <span className="text-xs text-muted-foreground">{items.length}</span>
      </div>
      <div className="space-y-2">{items.map(renderItem)}</div>
    </section>
  )
}

function CompactDiagnosticRow({
  primary,
  status,
}: {
  primary: ReactNode
  status: string
}) {
  return (
    <div className="rounded-md border border-border/70 bg-muted/20 px-3 py-1.5">
      <div className="flex items-center justify-between gap-3">
        <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
          {primary}
        </div>
        <StatusBadge tone={mapCheckTone(status)}>{status}</StatusBadge>
      </div>
    </div>
  )
}

function InlineMeta({ children }: { children: ReactNode }) {
  return <span className="text-xs text-muted-foreground">{children}</span>
}

function ChainStateBadge({
  isHealthy,
  children,
}: {
  isHealthy: boolean
  children: ReactNode
}) {
  return (
    <Badge size="xs" variant={isHealthy ? "success" : "warning"}>
      {children}
    </Badge>
  )
}

function PresenceBadge({
  label,
  present,
  yesLabel,
  noLabel,
}: {
  label: string
  present: boolean
  yesLabel: string
  noLabel: string
}) {
  return (
    <Badge size="xs" variant={present ? "success" : "warning"}>
      {label} {present ? yesLabel : noLabel}
    </Badge>
  )
}

function renderFirewallMark(
  expected: string | undefined,
  actual: string | undefined,
  t: (key: string, options?: Record<string, unknown>) => string
) {
  if (!expected && !actual) {
    return null
  }

  if (expected && actual && expected === actual) {
    return (
      <InlineMeta>
        {t("overview.routing.fwmarkLabel", { value: expected })}
      </InlineMeta>
    )
  }

  if (expected && actual) {
    return (
      <InlineMeta>
        {t("overview.routing.fwmarkExpectedActual", { expected, actual })}
      </InlineMeta>
    )
  }

  if (expected) {
    return (
      <InlineMeta>
        {t("overview.routing.fwmarkLabel", { value: expected })}
      </InlineMeta>
    )
  }

  return (
    <InlineMeta>
      {t("overview.routing.actualLabel", { value: actual })}
    </InlineMeta>
  )
}

function renderInlineDetail(detail?: string | null) {
  if (!detail) {
    return null
  }

  return <InlineMeta>{detail}</InlineMeta>
}

function groupRouteTables(routeTables: RouteTableCheck[]) {
  const groups = new Map<
    string,
    {
      key: string
      tableId: number
      outboundTag: string
      items: RouteTableCheck[]
    }
  >()

  routeTables.forEach((table) => {
    const key = `${table.table_id}:${table.outbound_tag}`
    const existing = groups.get(key)

    if (existing) {
      existing.items.push(table)
      return
    }

    groups.set(key, {
      key,
      tableId: table.table_id,
      outboundTag: table.outbound_tag,
      items: [table],
    })
  })

  return Array.from(groups.values())
}

function filterByHealth<T extends { status: string }>(
  items: T[],
  showHealthyEntries: boolean
) {
  if (showHealthyEntries) {
    return items
  }

  return items.filter((item) => item.status !== "ok")
}

function formatRouteExpectation(
  table: RouteTableCheck,
  t: (key: string, options?: Record<string, unknown>) => string
) {
  const parts = [
    table.expected_route_type ?? t("overview.routing.routeTypeFallback"),
  ]

  if (table.expected_interface) {
    parts.push(
      t("overview.routing.routeVia", { value: table.expected_interface })
    )
  }

  if (table.expected_gateway) {
    parts.push(
      t("overview.routing.routeGateway", { value: table.expected_gateway })
    )
  }

  if (typeof table.expected_metric === "number") {
    parts.push(
      t("overview.routing.routeMetric", { value: table.expected_metric })
    )
  }

  return parts.join(" ")
}

function getRouteMismatchDetail(
  table: RouteTableCheck,
  t: (key: string, options?: Record<string, unknown>) => string
) {
  const issues: string[] = []

  if (!table.table_exists) {
    issues.push(t("overview.routing.issues.tableMissing"))
  }

  if (!table.default_route_present) {
    issues.push(t("overview.routing.issues.defaultRouteMissing"))
  }

  if (!table.interface_matches) {
    issues.push(t("overview.routing.issues.interfaceMismatch"))
  }

  if (!table.gateway_matches) {
    issues.push(t("overview.routing.issues.gatewayMismatch"))
  }

  if (issues.length > 0) {
    return issues.join(", ")
  }

  return getDiagnosticDetail(table.status, table.detail)
}

function getDiagnosticDetail(status: string, detail?: string | null) {
  if (!detail || detail === "ok") {
    return status === "ok" ? null : null
  }

  return detail
}

function mapCheckTone(status: string): StatusTone {
  if (status === "ok") {
    return "healthy"
  }

  if (status === "missing") {
    return "warning"
  }

  return "degraded"
}

function StatusBadge({
  tone,
  children,
}: {
  tone: StatusTone
  children: string
}) {
  return (
    <Badge
      size="xs"
      variant={
        tone === "warning"
          ? "warning"
          : tone === "degraded"
            ? "destructive"
            : "success"
      }
    >
      {children}
    </Badge>
  )
}

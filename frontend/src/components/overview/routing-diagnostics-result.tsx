import {
  ChevronRight,
  CircleCheck,
  CircleHelp,
  CircleOff,
  CircleX,
} from "lucide-react"
import { useMemo, useState } from "react"
import { useTranslation } from "react-i18next"

import type {
  ConfigObject,
  RoutingTestEntry,
  RoutingTestResponse,
} from "@/api/generated/model"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Checkbox } from "@/components/ui/checkbox"
import { getListReferenceLabel } from "@/lib/list-display"
import { createOutboundDisplayNameMap } from "@/lib/outbound-display"
import { getRouteRuleDisplayName } from "@/pages/routing-rules-utils"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"

import { IpSetStateIcon } from "./ipset-state-icon"
import {
  formatRoutingFwmark,
  getRuleConditions,
  getRoutingPathStates,
  getVisibleRuleDiagnostics,
} from "./routing-diagnostics-utils"
import type { RoutingPathStepState } from "./routing-diagnostics-utils"
import { RoutingLegend } from "./routing-legend"

const emptyRuleDiagnostics: RoutingTestResponse["rule_diagnostics"] = []

export function RoutingDiagnosticsResult({
  diagnostics,
  lists,
  outbounds,
}: {
  diagnostics: RoutingTestResponse
  lists?: ConfigObject["lists"]
  outbounds?: ConfigObject["outbounds"]
}) {
  const { t } = useTranslation()
  const [showAllRules, setShowAllRules] = useState(false)
  const ruleDiagnostics = diagnostics.rule_diagnostics ?? emptyRuleDiagnostics
  const visibleRuleDiagnostics = useMemo(
    () => getVisibleRuleDiagnostics(ruleDiagnostics, showAllRules),
    [ruleDiagnostics, showAllRules]
  )
  const ipRows = diagnostics.is_domain
    ? diagnostics.resolved_ips
    : [diagnostics.target]
  const outboundDisplayNames = createOutboundDisplayNameMap(outbounds ?? [])
  const hasInsufficientContext = diagnostics.results.some(
    (result) => result.evaluation === "insufficient_context"
  )
  const getOutboundName = (outbound: string) => {
    if (outbound === "(default)") {
      return t("overview.routingDiagnostics.pathDefault")
    }
    if (outbound === "(unknown)") {
      return t("overview.routingDiagnostics.pathUnknown")
    }
    return outboundDisplayNames.get(outbound) ?? outbound
  }

  return (
    <div className="space-y-4">
      {(diagnostics.dns_error ||
        diagnostics.no_matching_rule ||
        diagnostics.unapplied_draft ||
        hasInsufficientContext) && (
        <Alert className="border-amber-400/40 bg-amber-50 text-amber-900">
          <AlertDescription className="space-y-1 text-sm">
            {diagnostics.dns_error ? <div>{diagnostics.dns_error}</div> : null}
            {diagnostics.no_matching_rule ? (
              <div>{t("overview.routingDiagnostics.noMatchingRule")}</div>
            ) : null}
            {diagnostics.unapplied_draft ? (
              <div>{t("overview.routingDiagnostics.unappliedDraft")}</div>
            ) : null}
            {hasInsufficientContext ? (
              <div>{t("overview.routingDiagnostics.insufficientContext")}</div>
            ) : null}
          </AlertDescription>
        </Alert>
      )}

      {diagnostics.results.length > 0 ? (
        <div className="space-y-4">
          <div className="space-y-3 rounded-md border bg-muted/20 p-3">
            <div className="space-y-0.5">
              <div className="font-medium">
                {t("overview.routingDiagnostics.pathTitle")}
              </div>
              <div className="text-xs text-muted-foreground">
                {t("overview.routingDiagnostics.pathDescription")}
              </div>
            </div>

            <div className="space-y-3">
              {diagnostics.results.map((result) => {
                const states = getRoutingPathStates(result)
                const mark = formatRoutingFwmark(result.kernel_route?.fwmark)
                const actualOutbound = getOutboundName(result.actual_outbound)
                const firewallValue = mark
                  ? t("overview.routingDiagnostics.pathFirewallMarked", {
                      outbound: actualOutbound,
                      mark,
                    })
                  : actualOutbound
                const kernelValue = getKernelRouteLabel(result, t)

                return (
                  <div
                    className="space-y-2 rounded-md border bg-background p-3"
                    key={`routing-path-${result.ip}`}
                  >
                    <div className="font-mono text-xs text-muted-foreground">
                      {result.ip}
                    </div>
                    <div className="grid items-stretch gap-2 md:grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)_auto_minmax(0,1fr)]">
                      <RoutingPathStep
                        label={t("overview.routingDiagnostics.pathRule")}
                        state={states.rule}
                        value={getOutboundName(result.expected_outbound)}
                      />
                      <ChevronRight className="mx-auto h-4 w-4 rotate-90 self-center text-muted-foreground md:rotate-0" />
                      <RoutingPathStep
                        label={t("overview.routingDiagnostics.pathFirewall")}
                        state={states.firewall}
                        value={firewallValue}
                      />
                      <ChevronRight className="mx-auto h-4 w-4 rotate-90 self-center text-muted-foreground md:rotate-0" />
                      <RoutingPathStep
                        label={t("overview.routingDiagnostics.pathKernel")}
                        state={states.kernel}
                        value={kernelValue}
                      />
                    </div>
                  </div>
                )
              })}
            </div>
          </div>

          <div className="space-y-2">
            <div className="font-medium">
              {t("overview.routingDiagnostics.resultTitle")}
            </div>
            <div className="overflow-x-auto rounded-md border">
              <Table className="min-w-[760px]">
                <TableHeader className="bg-muted/40">
                  <TableRow>
                    <TableHead>{t("overview.routingDiagnostics.ip")}</TableHead>
                    <TableHead>
                      {t("overview.routingDiagnostics.resultListMatch")}
                    </TableHead>
                    <TableHead>
                      {t("overview.routingDiagnostics.expectedOutbound")}
                    </TableHead>
                    <TableHead>
                      {t("overview.routingDiagnostics.actualOutbound")}
                    </TableHead>
                    <TableHead className="text-center">
                      {t("overview.routingDiagnostics.status")}
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {diagnostics.results.map((result) => {
                    const insufficient =
                      result.evaluation === "insufficient_context"
                    const listLabel = result.list_match
                      ? getListReferenceLabel(result.list_match.list, lists)
                      : null
                    return (
                      <TableRow key={result.ip}>
                        <TableCell className="font-mono text-sm">
                          {result.ip}
                        </TableCell>
                        <TableCell>
                          {result.list_match && listLabel ? (
                            <span
                              className="font-medium text-green-700"
                              title={result.list_match.list}
                            >
                              {result.list_match.via === result.ip
                                ? listLabel
                                : t(
                                    "overview.routingDiagnostics.resultListMatchVia",
                                    {
                                      list: listLabel,
                                      via: result.list_match.via,
                                    }
                                  )}
                            </span>
                          ) : (
                            <span className="text-muted-foreground">—</span>
                          )}
                        </TableCell>
                        <TableCell title={result.expected_outbound}>
                          {outboundDisplayNames.get(result.expected_outbound) ??
                            result.expected_outbound}
                        </TableCell>
                        <TableCell title={result.actual_outbound}>
                          {outboundDisplayNames.get(result.actual_outbound) ??
                            result.actual_outbound}
                        </TableCell>
                        <TableCell className="text-center">
                          <span
                            className={
                              insufficient
                                ? "inline-flex items-center gap-1 font-medium text-amber-700"
                                : result.ok
                                  ? "inline-flex items-center gap-1 font-medium text-green-700"
                                  : "inline-flex items-center gap-1 font-medium text-red-600"
                            }
                          >
                            {insufficient ? (
                              <CircleHelp className="h-4 w-4" />
                            ) : result.ok ? (
                              <CircleCheck className="h-4 w-4" />
                            ) : (
                              <CircleX className="h-4 w-4" />
                            )}
                            {insufficient
                              ? t("overview.routingDiagnostics.statusUnknown")
                              : result.ok
                                ? "OK"
                                : "NOK"}
                          </span>
                        </TableCell>
                      </TableRow>
                    )
                  })}
                </TableBody>
              </Table>
            </div>
          </div>
        </div>
      ) : null}

      {ruleDiagnostics.length > 0 ? (
        <div className="space-y-3">
          <div className="font-medium">
            {t("overview.routingDiagnostics.ruleDetailsTitle")}
          </div>
          <label className="flex items-center gap-2 text-sm text-muted-foreground">
            <Checkbox
              checked={showAllRules}
              onCheckedChange={(checked) => setShowAllRules(checked === true)}
            />
            <span>{t("overview.routingDiagnostics.showAllRules")}</span>
          </label>

          <div className="overflow-x-auto rounded-md border">
            <Table className="min-w-[720px]">
              <TableHeader className="bg-muted/40">
                <TableRow>
                  <TableHead className="min-w-48 font-semibold">
                    <div>
                      {t("overview.routingDiagnostics.hostLabel", {
                        target: diagnostics.target,
                      })}
                    </div>
                  </TableHead>
                  {visibleRuleDiagnostics.map((rule) => (
                    <TableHead
                      key={`rule-head-${rule.rule_index}`}
                      className="min-w-52 text-center align-top"
                    >
                      <div className="space-y-1 py-1">
                        <div className="font-semibold">
                          {getRouteRuleDisplayName(rule.rule, rule.rule_index)}
                        </div>
                        <div title={rule.outbound}>
                          {outboundDisplayNames.get(rule.outbound) ??
                            rule.outbound}
                        </div>
                        <div className="text-xs text-muted-foreground">
                          {rule.interface_name || t("common.noneShort")}
                        </div>
                        <RuleConditions lists={lists} rule={rule.rule} />
                      </div>
                    </TableHead>
                  ))}
                </TableRow>
                <TableRow>
                  <TableHead>
                    {t("overview.routingDiagnostics.inRuleLists")}
                  </TableHead>
                  {visibleRuleDiagnostics.map((rule) => (
                    <TableHead
                      key={`rule-list-${rule.rule_index}`}
                      className="text-center"
                    >
                      {rule.target_match ? (
                        <span className="text-xs font-medium text-green-700">
                          {t("overview.routingDiagnostics.listMatch", {
                            list: getListReferenceLabel(
                              rule.target_match.list,
                              lists
                            ),
                            via: rule.target_match.via,
                          })}
                        </span>
                      ) : (
                        <CircleOff className="mx-auto h-5 w-5 text-gray-400" />
                      )}
                    </TableHead>
                  ))}
                </TableRow>
              </TableHeader>
              <TableBody>
                {ipRows.map((ip) => (
                  <TableRow key={ip}>
                    <TableCell className="font-mono text-sm">{ip}</TableCell>
                    {visibleRuleDiagnostics.map((rule) => {
                      const ipDiag = rule.ip_rows.find((item) => item.ip === ip)
                      return (
                        <TableCell
                          key={`cell-${rule.rule_index}-${ip}`}
                          className="text-center"
                        >
                          <div className="space-y-1">
                            <IpSetStateIcon
                              targetInLists={ipDiag?.in_lists ?? false}
                              inIpset={ipDiag?.in_ipset}
                            />
                            {ipDiag?.list_match ? (
                              <div
                                className="text-xs font-medium text-green-700"
                                title={ipDiag.list_match.list}
                              >
                                {t("overview.routingDiagnostics.listMatch", {
                                  list: getListReferenceLabel(
                                    ipDiag.list_match.list,
                                    lists
                                  ),
                                  via: ipDiag.list_match.via,
                                })}
                              </div>
                            ) : null}
                            {ipDiag?.evaluation === "insufficient_context" ? (
                              <div
                                className="text-xs font-medium text-amber-700"
                                title={ipDiag.unknown_conditions.join(", ")}
                              >
                                {t(
                                  "overview.routingDiagnostics.packetContextRequired"
                                )}
                              </div>
                            ) : null}
                          </div>
                        </TableCell>
                      )
                    })}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </div>
      ) : null}

      <RoutingLegend />
    </div>
  )
}

function RoutingPathStep({
  label,
  state,
  value,
}: {
  label: string
  state: RoutingPathStepState
  value: string
}) {
  const Icon =
    state === "verified"
      ? CircleCheck
      : state === "failed"
        ? CircleX
        : state === "unknown"
          ? CircleHelp
          : CircleOff
  const tone =
    state === "verified"
      ? "border-green-300/60 bg-green-50/60 text-green-800"
      : state === "failed" || state === "blocked"
        ? "border-red-300/60 bg-red-50/60 text-red-700"
        : state === "unknown"
          ? "border-amber-300/60 bg-amber-50/60 text-amber-800"
          : "border-border bg-muted/30 text-muted-foreground"

  return (
    <div className={`min-w-0 rounded-md border px-3 py-2 ${tone}`}>
      <div className="text-xs font-medium opacity-80">{label}</div>
      <div className="mt-1 flex items-start gap-1.5">
        <Icon className="mt-0.5 h-4 w-4 shrink-0" />
        <span className="min-w-0 text-sm font-medium break-words">{value}</span>
      </div>
    </div>
  )
}

function getKernelRouteLabel(
  result: RoutingTestEntry,
  t: ReturnType<typeof useTranslation>["t"]
) {
  const kernelRoute = result.kernel_route

  switch (kernelRoute?.route_status) {
    case "resolved":
      if (kernelRoute.interface && kernelRoute.table != null) {
        return t("overview.routingDiagnostics.pathKernelResolvedTable", {
          interface: kernelRoute.interface,
          table: kernelRoute.table,
        })
      }
      if (kernelRoute.interface) {
        return t("overview.routingDiagnostics.pathKernelResolved", {
          interface: kernelRoute.interface,
        })
      }
      if (kernelRoute.table != null) {
        return t("overview.routingDiagnostics.pathKernelTableOnly", {
          table: kernelRoute.table,
        })
      }
      return t("overview.routingDiagnostics.pathUnknown")
    case "unroutable":
      return t("overview.routingDiagnostics.pathKernelUnroutable")
    case "not_applicable":
      return t("overview.routingDiagnostics.pathKernelNotApplicable")
    case "unavailable":
    default:
      return t("overview.routingDiagnostics.pathKernelUnavailable")
  }
}

function RuleConditions({
  lists,
  rule,
}: {
  lists?: ConfigObject["lists"]
  rule: RoutingTestResponse["rule_diagnostics"][number]["rule"]
}) {
  const { t } = useTranslation()
  const conditions = getRuleConditions(rule, lists)

  if (conditions.length === 0) {
    return (
      <div className="text-xs font-normal text-muted-foreground">
        {t("overview.routingDiagnostics.noConditions")}
      </div>
    )
  }

  return (
    <dl className="space-y-0.5 text-left text-xs font-normal text-muted-foreground">
      {conditions.map((condition) => (
        <div
          className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-1"
          key={condition.key}
        >
          <dt className="text-foreground">
            {t(`overview.routingDiagnostics.conditions.${condition.key}`)}:
          </dt>
          <dd className="wrap-break-words min-w-0 whitespace-normal">
            {condition.value}
          </dd>
        </div>
      ))}
    </dl>
  )
}

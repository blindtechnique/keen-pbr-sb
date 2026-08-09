import { CircleCheck, CircleHelp, CircleOff, CircleX } from "lucide-react"
import { useMemo, useState } from "react"
import { useTranslation } from "react-i18next"

import type { ConfigObject, RoutingTestResponse } from "@/api/generated/model"
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
  getRuleConditions,
  getVisibleRuleDiagnostics,
} from "./routing-diagnostics-utils"
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

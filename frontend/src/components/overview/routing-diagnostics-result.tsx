import { CircleCheck, CircleHelp, CircleX } from "lucide-react"
import { useMemo, useState } from "react"
import { useTranslation } from "react-i18next"

import type {
  ConfigObject,
  RoutingTestResponse,
  RoutingTestEntry,
  RoutingTestListMatch,
  RuntimeOutboundState,
} from "@/api/generated/model"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Checkbox } from "@/components/ui/checkbox"
import { getListReferenceLabel } from "@/lib/list-display"
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
import { RoutingEvidenceDetails } from "./routing-evidence-details"
import type { RoutingHttpProbeControls } from "./routing-http-probe-state"
import {
  getConfiguredRoutingOutbounds,
  getRoutingOutboundLabel,
  getSelectedRoutingGroupPath,
  isKnownRoutingOutbound,
} from "./routing-diagnostics-path"

const emptyRuleDiagnostics: RoutingTestResponse["rule_diagnostics"] = []

export function RoutingDiagnosticsResult({
  diagnostics,
  lists,
  outbounds,
  interfaceLabelFor,
  runtimeOutbounds = [],
  ...httpControls
}: {
  diagnostics: RoutingTestResponse
  lists?: ConfigObject["lists"]
  outbounds?: ConfigObject["outbounds"]
  interfaceLabelFor?: (name: string) => string
  runtimeOutbounds?: readonly RuntimeOutboundState[]
} & RoutingHttpProbeControls) {
  const { t } = useTranslation()
  const [showAllRules, setShowAllRules] = useState(false)
  const ruleDiagnostics = diagnostics.rule_diagnostics ?? emptyRuleDiagnostics
  const visibleRuleDiagnostics = useMemo(
    () => getVisibleRuleDiagnostics(ruleDiagnostics, showAllRules),
    [ruleDiagnostics, showAllRules]
  )
  const ipRows = [
    ...new Set([
      ...(diagnostics.is_domain
        ? diagnostics.resolved_ips
        : [diagnostics.target]),
      ...diagnostics.results.map((result) => result.ip),
    ]),
  ]
  const outboundLabel = (tag: string, iface?: string) => {
    if (tag === "(default)") return t("overview.routingDiagnostics.pathDefault")
    if (!isKnownRoutingOutbound(tag))
      return t("overview.routingDiagnostics.pathUnknown")
    const reportedInterface =
      iface ??
      ruleDiagnostics.find(
        (diagnostic) =>
          (diagnostic.rule.outbound || diagnostic.outbound) === tag
      )?.interface_name
    return getRoutingOutboundLabel(
      tag,
      outbounds ?? [],
      interfaceLabelFor,
      reportedInterface
    )
  }
  const groupSelection = (tag: string) => {
    const selected = getSelectedRoutingGroupPath(tag, runtimeOutbounds)
    if (!selected.length) return null
    return (
      <div className="text-xs font-normal text-muted-foreground">
        {t("overview.routingDiagnostics.selectedGroupMember", {
          member: selected
            .map((child) =>
              outboundLabel(child.outbound_tag, child.interface_name)
            )
            .join(" → "),
        })}
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {diagnostics.dns_error || diagnostics.unapplied_draft ? (
        <Alert className="border-amber-400/40 bg-amber-50 text-amber-900">
          <AlertDescription className="space-y-1 text-sm">
            {diagnostics.dns_error ? <div>{diagnostics.dns_error}</div> : null}
            {diagnostics.unapplied_draft ? (
              <div>{t("overview.routingDiagnostics.unappliedDraft")}</div>
            ) : null}
          </AlertDescription>
        </Alert>
      ) : null}
      {diagnostics.no_matching_rule ? (
        <p className="text-sm text-muted-foreground">
          {t("overview.routingDiagnostics.noMatchingRule")}
        </p>
      ) : null}

      {ipRows.length > 0 ? (
        <div className="space-y-3">
          <div className="font-medium">
            {t("overview.routingDiagnostics.ruleDetailsTitle")}
          </div>
          {ruleDiagnostics.length > 0 ? (
            <label className="flex items-center gap-2 text-sm text-muted-foreground">
              <Checkbox
                checked={showAllRules}
                onCheckedChange={(checked) => setShowAllRules(checked === true)}
              />
              <span>{t("overview.routingDiagnostics.showAllRules")}</span>
            </label>
          ) : null}
          <div className="overflow-x-auto rounded-md border">
            <Table className="min-w-[720px]">
              <TableHeader className="bg-muted/40">
                <TableRow>
                  <TableHead className="min-w-40 font-semibold">
                    {t("overview.routingDiagnostics.hostLabel", {
                      target: diagnostics.target,
                    })}
                  </TableHead>
                  <TableHead className="min-w-44">
                    {t("overview.routingDiagnostics.resultListMatch")}
                  </TableHead>
                  {visibleRuleDiagnostics.map((rule) => (
                    <TableHead
                      key={rule.rule_index}
                      className="min-w-48 text-center align-top"
                    >
                      <div className="space-y-1 py-1">
                        <div className="font-semibold">
                          {getRouteRuleDisplayName(rule.rule, rule.rule_index)}
                        </div>
                        <div title={rule.outbound}>
                          {outboundLabel(
                            rule.rule.outbound || rule.outbound,
                            rule.interface_name
                          )}
                          {groupSelection(rule.rule.outbound || rule.outbound)}
                        </div>
                        <details className="text-xs font-normal text-muted-foreground">
                          <summary className="cursor-pointer">
                            {t("overview.routingDiagnostics.ruleConditions")}
                          </summary>
                          <RuleConditions lists={lists} rule={rule.rule} />
                        </details>
                      </div>
                    </TableHead>
                  ))}
                  <TableHead className="min-w-40">
                    {t("overview.routingDiagnostics.appliedRoute")}
                  </TableHead>
                  <TableHead className="text-center">
                    {t("overview.routingDiagnostics.status")}
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {ipRows.map((ip) => {
                  const result = diagnostics.results.find(
                    (entry) => entry.ip === ip
                  )
                  const actual = isKnownRoutingOutbound(result?.actual_outbound)
                    ? result.actual_outbound
                    : undefined
                  const configured = getConfiguredRoutingOutbounds(
                    result,
                    ip,
                    ruleDiagnostics
                  )
                  const matches = [
                    ...new Map(
                      [
                        ...(result?.list_matches ?? []),
                        ...(result?.list_match ? [result.list_match] : []),
                        ...ruleDiagnostics.flatMap((rule) => {
                          const match =
                            rule.ip_rows.find((row) => row.ip === ip)
                              ?.list_match ?? rule.target_match
                          return match ? [match] : []
                        }),
                      ].map((match) => [`${match.list}:${match.via}`, match])
                    ).values(),
                  ]
                  return (
                    <TableRow key={ip}>
                      <TableCell className="font-mono text-sm">{ip}</TableCell>
                      <TableCell>
                        {matches.length ? (
                          matches.map((match) => (
                            <ListMatch
                              key={`${match.list}:${match.via}`}
                              match={match}
                              ip={ip}
                              lists={lists}
                            />
                          ))
                        ) : (
                          <span className="text-muted-foreground">
                            {t("overview.routingDiagnostics.listNotFound")}
                          </span>
                        )}
                      </TableCell>
                      {visibleRuleDiagnostics.map((rule) => {
                        const ipDiag = rule.ip_rows.find(
                          (item) => item.ip === ip
                        )
                        return (
                          <TableCell
                            key={`${rule.rule_index}-${ip}`}
                            className="text-center"
                          >
                            <IpSetStateIcon
                              targetInLists={ipDiag?.in_lists ?? false}
                              inIpset={ipDiag?.in_ipset}
                            />
                          </TableCell>
                        )
                      })}
                      <TableCell>
                        <div className="space-y-2">
                          {actual ? (
                            <div className="font-medium">
                              {outboundLabel(actual)}
                              {groupSelection(actual)}
                            </div>
                          ) : null}
                          {configured
                            .filter((tag) => tag !== actual)
                            .map((tag) => (
                              <div key={tag}>
                                <div className="text-xs text-muted-foreground">
                                  {t(
                                    "overview.routingDiagnostics.configuredPath"
                                  )}
                                </div>
                                <div className="font-medium">
                                  {outboundLabel(tag)}
                                </div>
                                {groupSelection(tag)}
                              </div>
                            ))}
                          {!actual && !configured.length
                            ? outboundLabel("(unknown)")
                            : null}
                        </div>
                      </TableCell>
                      <TableCell className="text-center">
                        <RoutingStatus result={result} />
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          </div>
          {visibleRuleDiagnostics.length > 0 ? <RoutingLegend /> : null}
        </div>
      ) : null}
      <RoutingEvidenceDetails
        diagnostics={diagnostics}
        lists={lists}
        {...httpControls}
      >
        {diagnostics.results.some(
          (result) => result.evaluation === "insufficient_context"
        ) ? (
          <p className="text-muted-foreground">
            {t("overview.routingDiagnostics.insufficientContext")}
          </p>
        ) : null}
        {diagnostics.results.length > 0 ? (
          <dl className="space-y-2">
            {diagnostics.results.map((result) => (
              <div key={result.ip}>
                <dt className="font-mono">{result.ip}</dt>
                <dd>
                  {t("overview.routingDiagnostics.expectedOutbound")}:{" "}
                  {outboundLabel(result.expected_outbound)}
                </dd>
                <dd>
                  {t("overview.routingDiagnostics.actualOutbound")}:{" "}
                  {outboundLabel(result.actual_outbound)}
                </dd>
              </div>
            ))}
          </dl>
        ) : null}
      </RoutingEvidenceDetails>
    </div>
  )
}

function ListMatch({
  match,
  ip,
  lists,
}: {
  match: RoutingTestListMatch
  ip: string
  lists?: ConfigObject["lists"]
}) {
  const { t } = useTranslation()
  const label = getListReferenceLabel(match.list, lists)
  return (
    <div className="font-medium text-green-700" title={match.list}>
      {match.via === ip
        ? label
        : t("overview.routingDiagnostics.resultListMatchVia", {
            list: label,
            via: match.via,
          })}
    </div>
  )
}

function RoutingStatus({ result }: { result?: RoutingTestEntry }) {
  const { t } = useTranslation()
  const unknown =
    !result ||
    result.evaluation === "insufficient_context" ||
    result.expected_outbound === "(unknown)" ||
    result.actual_outbound === "(unknown)"
  const Icon = unknown ? CircleHelp : result.ok ? CircleCheck : CircleX
  return (
    <span
      className={`inline-flex items-center gap-1 font-medium ${unknown ? "text-muted-foreground" : result.ok ? "text-green-700" : "text-red-600"}`}
    >
      <Icon aria-hidden="true" className="h-4 w-4 shrink-0" />
      {unknown
        ? t("overview.routingDiagnostics.pathUnknown")
        : result.ok
          ? "OK"
          : t("overview.routingDiagnostics.routeMismatch")}
    </span>
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
  if (conditions.length === 0)
    return (
      <div className="text-xs font-normal text-muted-foreground">
        {t("overview.routingDiagnostics.noConditions")}
      </div>
    )
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

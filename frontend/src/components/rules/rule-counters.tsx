import { useEffect, useRef, useState } from "react"
import { useTranslation } from "react-i18next"
import { getRoutingCounters } from "@/api/generated/keen-api"
import type { RuleCountersResponse } from "@/api/generated/model/ruleCountersResponse"
import type { RuleCounterEntry } from "@/api/generated/model/ruleCounterEntry"
import type { RoutingTestFirewallCounters } from "@/api/generated/model/routingTestFirewallCounters"
import { Button } from "@/components/ui/button"
import { FirewallCounterEvidence } from "@/components/overview/routing-evidence-details"
import { formatEvidenceTime } from "@/components/overview/routing-evidence-model"
import { runRuleCounters, type RuleCountersState } from "./rule-counters-model"

export function RuleCountersSession({
  localChanges,
}: {
  localChanges: boolean
}) {
  const { t } = useTranslation()
  const [state, setState] = useState<RuleCountersState>({ status: "idle" })
  const active = useRef<AbortController | null>(null)
  useEffect(
    () => () => {
      const controller = active.current
      active.current = null
      controller?.abort()
    },
    []
  )
  return (
    <div className="mt-3 space-y-3 text-sm">
      <p className="text-muted-foreground">{t("ruleCounters.description")}</p>
      <details className="rounded border p-2">
        <summary className="cursor-pointer">
          {t("ruleCounters.limitsTitle")}
        </summary>
        <div className="mt-2 space-y-2 text-muted-foreground">
          <p>{t("ruleCounters.units")}</p>
          <p>{t("ruleCounters.fastPath")}</p>
          <p>{t("ruleCounters.overlap")}</p>
          <p>{t("ruleCounters.reset")}</p>
          <p>{t("ruleCounters.noTotals")}</p>
        </div>
      </details>
      {localChanges ? <p>{t("ruleCounters.localChanges")}</p> : null}
      <Button
        type="button"
        size="sm"
        variant="outline"
        aria-disabled={state.status === "pending"}
        aria-busy={state.status === "pending"}
        onClick={() =>
          void runRuleCounters(
            active,
            async (signal) => {
              const response = await getRoutingCounters({
                signal,
                cache: "no-store",
              })
              return response.status === 200 ? response.data : undefined
            },
            setState
          )
        }
      >
        {t("ruleCounters.read")}
      </Button>
      <div role="status" aria-live="polite" aria-atomic="true">
        {state.status === "pending" ? t("ruleCounters.pending") : null}
        {state.status === "failed" ? t("ruleCounters.failed") : null}
        {state.status === "ready"
          ? t("ruleCounters.done", { count: state.result.rules.length })
          : null}
      </div>
      {state.status === "ready" ? (
        <RuleCountersResult result={state.result} />
      ) : null}
    </div>
  )
}

function CounterSummary({
  counters,
}: {
  counters: RoutingTestFirewallCounters
}) {
  const { t } = useTranslation()
  if (counters.status === "observed") {
    const single =
      counters.total === 1 && counters.rules.length === 1 && !counters.truncated
    return (
      <>
        {single
          ? t("overview.routingDiagnostics.evidence.counterTotals", {
              packets: counters.rules[0].packets,
              bytes: counters.rules[0].bytes,
            })
          : t("ruleCounters.physicalRows", {
              count: counters.rules.length,
              total: counters.total,
            })}
      </>
    )
  }
  return (
    <>
      {counters.status === "ambiguous"
        ? t("ruleCounters.ambiguous")
        : counters.status === "not_applicable"
          ? t("ruleCounters.notApplicable")
          : t("ruleCounters.unavailable")}
    </>
  )
}

export function RuleCounterDetails({ rule }: { rule: RuleCounterEntry }) {
  const { t } = useTranslation()
  return (
    <div className="mt-3 grid gap-3 lg:grid-cols-2">
      <section className="min-w-0">
        <h4 className="font-medium">{t("ruleCounters.ipv4")}</h4>
        <FirewallCounterEvidence counters={rule.ipv4} />
      </section>
      <section className="min-w-0">
        <h4 className="font-medium">{t("ruleCounters.ipv6")}</h4>
        <FirewallCounterEvidence counters={rule.ipv6} />
      </section>
    </div>
  )
}

function RuleCounterRow({ rule }: { rule: RuleCounterEntry }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  return (
    <details
      className="rounded-md border p-3"
      onToggle={(event) => setOpen(event.currentTarget.open)}
    >
      <summary className="cursor-pointer space-y-1 break-words">
        <span className="font-medium">
          #{rule.rule_index + 1} {rule.name || t("ruleCounters.unnamed")}
        </span>
        {" · "}
        {t("ruleCounters.outbound", { name: rule.outbound_name })}
        {!rule.enabled ? <> · {t("ruleCounters.disabled")}</> : null}
        <span className="block text-xs text-muted-foreground">
          {t("ruleCounters.ipv4")} · <CounterSummary counters={rule.ipv4} />
        </span>
        <span className="block text-xs text-muted-foreground">
          {t("ruleCounters.ipv6")} · <CounterSummary counters={rule.ipv6} />
        </span>
      </summary>
      {open ? <RuleCounterDetails rule={rule} /> : null}
    </details>
  )
}

export function RuleCountersResult({
  result,
}: {
  result: RuleCountersResponse
}) {
  const { t } = useTranslation()
  return (
    <div className="space-y-3">
      <p className="text-muted-foreground">
        {t("ruleCounters.snapshot", {
          time:
            formatEvidenceTime(result.captured_at) ??
            t("overview.routingDiagnostics.statusUnknown"),
          count: result.rules.length,
          total: result.total,
        })}
      </p>
      {result.unapplied_draft ? <p>{t("ruleCounters.draft")}</p> : null}
      {result.truncated ? <p>{t("ruleCounters.truncated")}</p> : null}
      {result.rules.length === 0 ? <p>{t("ruleCounters.empty")}</p> : null}
      {result.rules.map((rule) => (
        <RuleCounterRow key={rule.rule_index} rule={rule} />
      ))}
    </div>
  )
}

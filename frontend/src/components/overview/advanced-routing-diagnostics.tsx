import { useState } from "react"
import { useTranslation } from "react-i18next"
import { RuleCountersSession } from "@/components/rules/rule-counters"

/** Technical tools stay outside routine rule editing and never auto-run. */
export function AdvancedRoutingDiagnostics() {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  return (
    <details
      className="mt-4 border-t pt-3"
      onToggle={(event) => setOpen(event.currentTarget.open)}
    >
      <summary className="cursor-pointer text-sm font-medium">
        {t("overview.routing.advancedTitle")}
      </summary>
      {open ? (
        <section className="mt-3 text-sm" aria-label={t("ruleCounters.title")}>
          <p className="mb-3 text-muted-foreground">
            {t("overview.routing.advancedDescription")}
          </p>
          <h3 className="font-medium">{t("ruleCounters.title")}</h3>
          <RuleCountersSession localChanges={false} />
        </section>
      ) : null}
    </details>
  )
}

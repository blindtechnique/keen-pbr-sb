import { useEffect, useRef, useState } from "react"
import { useTranslation } from "react-i18next"
import { Link } from "wouter"
import { postListHints } from "@/api/generated/keen-api"
import type { ConfigObject } from "@/api/generated/model/configObject"
import type { ListHintsResponse } from "@/api/generated/model/listHintsResponse"
import { Button } from "@/components/ui/button"
import { getListReferenceLabel } from "@/lib/list-display"
import {
  listHintsIncomplete,
  listHintSourceText,
  listHintText,
  runListHints,
  type ListHintsState,
} from "./list-hints-model"

export function ListHints({
  config,
  revision,
}: {
  config: ConfigObject
  revision: string
}) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  return (
    <details
      className="rounded-md border border-border p-3"
      onToggle={(event) => setOpen(event.currentTarget.open)}
    >
      <summary className="cursor-pointer text-sm font-medium">
        {t("listHints.title")}
      </summary>
      {open ? (
        <HintsSession key={revision} config={config} revision={revision} />
      ) : null}
    </details>
  )
}

function HintsSession({
  config,
  revision,
}: {
  config: ConfigObject
  revision: string
}) {
  const { t } = useTranslation()
  const [state, setState] = useState<ListHintsState>({ status: "idle" })
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
      <p className="text-muted-foreground">{t("listHints.description")}</p>
      <Button
        type="button"
        variant="outline"
        size="sm"
        aria-disabled={state.status === "pending"}
        aria-busy={state.status === "pending"}
        onClick={() =>
          void runListHints(
            active,
            revision,
            async (signal) => {
              const response = await postListHints({ signal })
              if (response.status !== 200) return Promise.reject()
              return response.data
            },
            setState
          )
        }
      >
        {t("listHints.check")}
      </Button>
      <div role="status" aria-live="polite" aria-atomic="true">
        {state.status === "pending" ? t("listHints.loading") : null}
        {state.status === "failed" ? t("listHints.failed") : null}
        {state.status === "stale" ? t("listHints.stale") : null}
        {state.status === "ready"
          ? t("listHints.done", { count: state.result.items.length })
          : null}
      </div>
      {state.status === "ready" ? (
        <ListHintsResult result={state.result} config={config} />
      ) : null}
    </div>
  )
}

export function ListHintsResult({
  result,
  config,
}: {
  result: ListHintsResponse
  config: ConfigObject
}) {
  const { t } = useTranslation()
  const listLink = (id: string) => (
    <Link
      href={`/lists/${encodeURIComponent(id)}/edit`}
      className="break-all text-primary underline underline-offset-2"
    >
      {getListReferenceLabel(id, config.lists)}
    </Link>
  )
  return (
    <div className="min-w-0 space-y-3 [overflow-wrap:anywhere]">
      <p className="text-muted-foreground">{t("listHints.scope")}</p>
      {result.is_draft ? <p>{t("listHints.draft")}</p> : null}
      <p className="text-muted-foreground">
        {t("listHints.stats", {
          lists: result.scanned_lists,
          total: result.total_lists,
          entries: result.scanned_entries,
        })}
      </p>
      {listHintsIncomplete(result) ? <p>{t("listHints.partial")}</p> : null}
      {result.hints_limited ? <p>{t("listHints.samples")}</p> : null}
      {result.conditional_rules > 0 ? (
        <p className="text-muted-foreground">
          {t("listHints.conditions", { count: result.conditional_rules })}
        </p>
      ) : null}
      {result.items.length === 0 ? (
        <p>{t("listHints.empty")}</p>
      ) : (
        <ul className="space-y-3">
          {result.items.map((hint, index) => (
            <li key={index} className="space-y-1 border-l-2 border-border pl-3">
              <div className="flex flex-wrap gap-x-3">
                {listLink(hint.list)}
                {hint.other_list && hint.other_list !== hint.list
                  ? listLink(hint.other_list)
                  : null}
              </div>
              <p>{listHintText(hint, config, t)}</p>
            </li>
          ))}
        </ul>
      )}
      {result.source_issues.length > 0 ? (
        <details className="space-y-2">
          <summary className="cursor-pointer">
            {t("listHints.sources.title")}
          </summary>
          <ul className="space-y-2">
            {result.source_issues.map((issue, index) => (
              <li key={index}>
                {listLink(issue.list)}: {listHintSourceText(issue.reason, t)}
              </li>
            ))}
          </ul>
        </details>
      ) : null}
    </div>
  )
}

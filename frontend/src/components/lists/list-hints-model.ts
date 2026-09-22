import type { TFunction } from "i18next"
import type { ConfigObject } from "@/api/generated/model/configObject"
import type { ListHint } from "@/api/generated/model/listHint"
import type { ListHintsResponse } from "@/api/generated/model/listHintsResponse"
import { createOutboundDisplayNameMap } from "@/lib/outbound-display"

export type ListHintsState =
  | { status: "idle" | "pending" | "failed" | "stale" }
  | { status: "ready"; result: ListHintsResponse }

export async function runListHints(
  active: { current: AbortController | null },
  revision: string,
  request: (signal: AbortSignal) => Promise<ListHintsResponse>,
  publish: (state: ListHintsState) => void
): Promise<void> {
  if (active.current) return
  const controller = new AbortController()
  active.current = controller
  publish({ status: "pending" })
  try {
    const result = await request(controller.signal)
    if (active.current !== controller) return
    publish(
      result.revision === revision
        ? { status: "ready", result }
        : { status: "stale" }
    )
  } catch {
    // Never expose exception text containing source credentials or file paths.
    if (active.current === controller) publish({ status: "failed" })
  } finally {
    if (active.current === controller) active.current = null
  }
}

export function listHintText(
  hint: ListHint,
  config: ConfigObject,
  t: TFunction
): string {
  if (hint.code === "unused") return t("listHints.unused")
  if (hint.code === "wide_cidr")
    return t("listHints.wide", { entry: hint.entry ?? "" })
  if (hint.code !== "domain_overlap") return t("listHints.unknown")
  const names = createOutboundDisplayNameMap(config.outbounds ?? [])
  return t("listHints.overlap", {
    entry: hint.entry ?? "",
    otherEntry: hint.other_entry ?? "",
    earlier: (hint.rule_index ?? 0) + 1,
    later: (hint.other_rule_index ?? 0) + 1,
    outbound: names.get(hint.outbound ?? "") ?? hint.outbound ?? "",
    otherOutbound:
      names.get(hint.other_outbound ?? "") ?? hint.other_outbound ?? "",
  })
}

export function listHintSourceText(reason: string, t: TFunction): string {
  switch (reason) {
    case "source_changed":
      return t("listHints.sources.changed")
    case "size_limit":
      return t("listHints.sources.large")
    case "invalid_source":
      return t("listHints.sources.invalid")
    default:
      return t("listHints.sources.unavailable")
  }
}

export function listHintsIncomplete(result: ListHintsResponse): boolean {
  return (
    result.scan_limited ||
    result.source_issues_limited ||
    result.source_issues.length > 0 ||
    result.scanned_lists < result.total_lists
  )
}

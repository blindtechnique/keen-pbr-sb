// The transport supervisor reports a failure as one opaque English string.
//
// It is composed in the Go transport-manager as
// "keen-pbr routing health: <verdict>: <detail>", where the detail is whatever
// libcurl said. Rendering that verbatim puts an internal component's name and
// an English sentence in front of an operator - and this paragraph is the only
// place the reason appears at all, so it cannot simply be dropped either.
//
// So: recognise the shape, translate what the panel already has words for, and
// pass anything else through untouched. A message this build does not
// understand is still a message the operator needs.

import type { OutboundRuntimeIssue } from "@/components/overview/outbound-state-model"
import { runtimeDetailCode } from "@/components/overview/outbound-state-model"

const ROUTING_HEALTH_PREFIX = "keen-pbr routing health: "

export type TransportErrorText =
  | { kind: "issue"; code: OutboundRuntimeIssue["code"] }
  | { kind: "raw"; text: string }

export function transportErrorText(
  raw: string | undefined
): TransportErrorText | null {
  const text = raw?.trim()
  if (!text) {
    return null
  }
  if (!text.startsWith(ROUTING_HEALTH_PREFIX)) {
    // Not the supervisor's routing-health line. Whatever it is, the operator
    // sees it exactly as it arrived rather than losing it to a classifier
    // that was never meant for it.
    return { kind: "raw", text }
  }

  const rest = text.slice(ROUTING_HEALTH_PREFIX.length)
  const separator = rest.indexOf(": ")
  const verdict = separator >= 0 ? rest.slice(0, separator) : rest
  const detail = separator >= 0 ? rest.slice(separator + 2) : ""

  // The same classifier the dashboard uses, so one daemon detail cannot mean
  // two different things depending on which page is showing it. The verdict
  // is the fallback: when the detail says nothing recognisable, "degraded"
  // still names the state.
  return { kind: "issue", code: runtimeDetailCode(detail, verdict) }
}

// What the exit check says, as pure functions.
//
// The daemon returns two measurements and two classifications; the panel's
// only job is to pick the sentence that matches, and to keep "we could not
// attribute this" from being rendered as either good or bad news.

import type { TransportExitCheckResponse } from "@/api/generated/model"

export type ExitCheckTone = "success" | "warning" | "danger" | "info"

export type ExitCheckSummary = {
  tone: ExitCheckTone
  titleKey: string
  // Filled from the response, so the sentence can name the addresses that
  // were actually seen rather than describing them in the abstract.
  through?: string
  direct?: string
}

export function exitCheckSummary(
  result: TransportExitCheckResponse | undefined
): ExitCheckSummary | null {
  if (!result) {
    return null
  }

  // Attribution first, and it is never "success". The request may well have
  // returned an address; it is just not this transport's address, and dressing
  // it up either way is the failure this check exists to avoid.
  if (result.verdict === "unattributed") {
    return { tone: "info", titleKey: "transports.exitCheck.unattributed" }
  }
  if (result.verdict === "unreachable") {
    return { tone: "danger", titleKey: "transports.exitCheck.unreachable" }
  }

  const through = result.through?.address || undefined
  const direct = result.direct?.address || undefined

  // Working, and the world sees a different address: the one unambiguous
  // "your traffic goes through the tunnel" answer.
  if (result.exit_address === "changed") {
    return {
      tone: "success",
      titleKey: "transports.exitCheck.changed",
      through,
      direct,
    }
  }
  // Working, but the same address on both sides. The tunnel answered, yet
  // nothing about the operator's visible address changed - worth a warning
  // rather than a green tick, because this is what a bypassed tunnel looks
  // like from outside.
  if (result.exit_address === "same") {
    return {
      tone: "warning",
      titleKey: "transports.exitCheck.same",
      through,
      direct,
    }
  }
  // Working, but the control did not answer, so there is nothing to compare
  // against. The traffic demonstrably left through the device; that is all
  // this run can honestly claim.
  return { tone: "info", titleKey: "transports.exitCheck.noControl", through }
}

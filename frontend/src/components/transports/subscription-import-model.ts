import type { SubscriptionPreviewCandidate } from "@/api/generated/model"
import { SubscriptionPreviewCandidateDisposition } from "@/api/generated/model"
import type { SubscriptionApplySelection } from "@/api/generated/model"

// Selection logic for the subscription import dialog, kept apart from the
// component so the decisions - what may be selected, what blocks an apply,
// what is actually sent - are testable as functions rather than as clicks.
//
// The backend is the authority on every rule repeated here; these checks exist
// so the operator learns about a problem while looking at the table, not from
// a per-entry failure after the fact. Anything this module lets through and
// the backend refuses is reported per entry by the apply response.

const TAG_PATTERN = /^[a-z][a-z0-9_]{0,23}$/

export function isValidTag(tag: string) {
  return TAG_PATTERN.test(tag)
}

// tag_conflict is selectable because the operator can resolve it by renaming;
// everything else that is not importable stays unselectable - a duplicate or
// an unsupported scheme does not become sensible because it has a checkbox.
export function isSelectable(candidate: SubscriptionPreviewCandidate) {
  return (
    candidate.disposition ===
      SubscriptionPreviewCandidateDisposition.importable ||
    candidate.disposition ===
      SubscriptionPreviewCandidateDisposition.tag_conflict
  )
}

export function requiresTagOverride(candidate: SubscriptionPreviewCandidate) {
  return (
    candidate.disposition ===
    SubscriptionPreviewCandidateDisposition.tag_conflict
  )
}

// Importable entries start selected: the common case is "import what is new".
// Conflicts start unselected, because selecting one is a decision (a rename)
// the operator has to make, not a default they have to notice and undo.
export function initialSelectedLines(
  candidates: SubscriptionPreviewCandidate[]
): Set<number> {
  const selected = new Set<number>()
  for (const candidate of candidates) {
    if (
      candidate.disposition ===
      SubscriptionPreviewCandidateDisposition.importable
    ) {
      selected.add(candidate.line)
    }
  }
  return selected
}

export function effectiveTag(
  candidate: SubscriptionPreviewCandidate,
  overrides: ReadonlyMap<number, string>
) {
  const override = overrides.get(candidate.line)?.trim()
  if (override) return override
  return candidate.suggested_tag ?? ""
}

export type SelectionProblem = {
  line: number
  kind: "tag_required" | "tag_invalid" | "tag_duplicate"
}

// Everything that must stop the apply button, in one pass: a conflict left
// unrenamed, an override that does not match the tag pattern, and two selected
// entries resolving to one tag - the last is the operator's own edit creating
// the very collision the preview named, and it must surface before the
// request, not as one created entry and one failed one.
export function selectionProblems(
  candidates: SubscriptionPreviewCandidate[],
  selected: ReadonlySet<number>,
  overrides: ReadonlyMap<number, string>
): SelectionProblem[] {
  const problems: SelectionProblem[] = []
  const tagOwners = new Map<string, number>()
  for (const candidate of candidates) {
    if (!selected.has(candidate.line) || !isSelectable(candidate)) {
      continue
    }
    const override = overrides.get(candidate.line)?.trim() ?? ""
    // A conflict is resolved by a *different* name: retyping the very tag the
    // preview flagged as taken would sail through here and fail per-entry at
    // the manager, which is the late failure this check exists to prevent.
    if (
      requiresTagOverride(candidate) &&
      (!override || override === candidate.suggested_tag)
    ) {
      problems.push({ line: candidate.line, kind: "tag_required" })
      continue
    }
    if (override && !isValidTag(override)) {
      problems.push({ line: candidate.line, kind: "tag_invalid" })
      continue
    }
    const tag = effectiveTag(candidate, overrides)
    if (!tag) {
      problems.push({ line: candidate.line, kind: "tag_required" })
      continue
    }
    const owner = tagOwners.get(tag)
    if (owner !== undefined) {
      problems.push({ line: candidate.line, kind: "tag_duplicate" })
      continue
    }
    tagOwners.set(tag, candidate.line)
  }
  return problems
}

// The request body. Only lines that are selected AND selectable are sent, and
// the tag travels only when the operator actually overrode it - the backend
// derives the same suggestion, and sending it back would turn a display
// default into an assertion.
export function buildSelections(
  candidates: SubscriptionPreviewCandidate[],
  selected: ReadonlySet<number>,
  overrides: ReadonlyMap<number, string>
): SubscriptionApplySelection[] {
  const selections: SubscriptionApplySelection[] = []
  for (const candidate of candidates) {
    if (!selected.has(candidate.line) || !isSelectable(candidate)) {
      continue
    }
    const override = overrides.get(candidate.line)?.trim()
    if (override) {
      selections.push({ line: candidate.line, tag: override })
    } else {
      selections.push({ line: candidate.line })
    }
  }
  return selections
}

// What the operator pasted into the one field the add-transport modal offers.
//
// There is no second field and no mode switch, because the two things are
// distinguishable without asking: a share link carries the protocol in its
// scheme (vless://, vmess://, ss://, vpn://…), and a subscription is an
// ordinary web address the provider hands out. http/https is therefore the
// whole rule - no share-link scheme is http, and no subscription is fetched
// over anything else.
//
// Deliberately not a list of known share-link schemes: that list would need
// updating every time a protocol appears, and the failure mode would be
// silently treating a new scheme as a subscription URL.
export type PastedLinkKind = "subscription" | "share-link" | "empty"

export function classifyPastedLink(value: string): PastedLinkKind {
  const trimmed = value.trim()
  if (trimmed.length === 0) return "empty"
  const scheme = trimmed.slice(0, trimmed.indexOf(":")).toLowerCase()
  return scheme === "http" || scheme === "https"
    ? "subscription"
    : "share-link"
}

// A file dropped into the import tab. WireGuard configurations start with a
// section header; anything else is offered to the subscription planner, which
// is the component that can actually say what a document is - it recognises a
// link list, a base64 list, a sing-box JSON document, and says so by name.
//
// The check is positive on the WireGuard side rather than negative on the
// other: "not a subscription" is not a thing this frontend can determine, and
// pretending it could would send readable subscriptions to the WireGuard
// parser to fail with the wrong message.
export function looksLikeWireGuardConfig(text: string): boolean {
  return /^\s*\[(Interface|Peer)\]/im.test(text)
}

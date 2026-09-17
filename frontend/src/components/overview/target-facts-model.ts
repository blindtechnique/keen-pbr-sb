import type {
  RoutingTestNfqws,
  RoutingTestNfqwsMatch,
  RoutingTestNfqwsProfile,
} from "@/api/generated/model"

/**
 * Three separate answers about one target, kept separate on purpose.
 *
 * "Covered by nfqws", "on the registry" and "reachable" are different facts
 * from different sources, and any two of them can disagree without either
 * being wrong: a site can be on the registry and work, or be absent from it
 * and fail through a blocked CDN prefix. Merging them into one verdict would
 * have to pick a winner, and it would be wrong in both directions.
 */
export type NfqwsCoverage = {
  readonly known: boolean
  /** Why coverage is unknown, when the API can distinguish it. */
  readonly reason?: RoutingTestNfqws["reason"]
  /** Matching include entries, not proof that nfqws processes a packet. */
  readonly covering: readonly RoutingTestNfqwsMatch[]
  /** Matching exclude entries, whose effect is local to their profile. */
  readonly excluding: readonly RoutingTestNfqwsMatch[]
  readonly profiles: readonly RoutingTestNfqwsProfile[]
}

export function summariseNfqwsCoverage(
  nfqws: RoutingTestNfqws | undefined
): NfqwsCoverage {
  if (!nfqws?.available) {
    return {
      known: false,
      reason: nfqws?.reason,
      covering: [],
      excluding: [],
      profiles: nfqws?.profiles ?? [],
    }
  }
  const matches = nfqws.matches ?? []
  return {
    known: true,
    covering: matches.filter((match) => match.includes),
    excluding: matches.filter((match) => !match.includes),
    profiles: nfqws.profiles ?? [],
  }
}

/**
 * What to say about nfqws in one line.
 *
 * Exclusions are local to a profile. A target-only request cannot determine
 * the winning profile for a packet without its port/protocol/visible host.
 * Even legacy flat evidence must never claim global exclusion precedence.
 */
export type NfqwsVerdict =
  | "busy"
  | "unknown"
  | "excluded"
  | "covered"
  | "uncovered"
  | "mixed"

export const nfqwsProfileResults = [
  "matched",
  "excluded",
  "unmatched",
  "unrestricted",
  "mixed",
  "unknown",
  "hostname_required",
  "ip_required",
  "auto_pending",
] as const
export type NfqwsProfileResult = (typeof nfqwsProfileResults)[number]

export function nfqwsProfileResult(
  profile: RoutingTestNfqwsProfile
): NfqwsProfileResult {
  return nfqwsProfileResults.includes(profile.list_result as NfqwsProfileResult)
    ? (profile.list_result as NfqwsProfileResult)
    : "unknown"
}

export function nfqwsVerdict(coverage: NfqwsCoverage): NfqwsVerdict {
  if (!coverage.known && coverage.reason === "busy") return "busy"
  if (!coverage.known) return "unknown"
  if (coverage.profiles.length) {
    const results = coverage.profiles.map(nfqwsProfileResult)
    if (
      results.some((result) =>
        ["unknown", "hostname_required", "ip_required"].includes(result)
      )
    )
      return "unknown"
    const matched = coverage.profiles.some(
      (profile) =>
        profile.has_actions !== false &&
        ["matched", "unrestricted"].includes(nfqwsProfileResult(profile))
    )
    const excluded = results.includes("excluded")
    if (results.includes("mixed") || (matched && excluded)) return "mixed"
    if (excluded) return "excluded"
    return matched ? "covered" : "uncovered"
  }
  if (coverage.excluding.length > 0 && coverage.covering.length > 0)
    return "mixed"
  if (coverage.excluding.length > 0) return "excluded"
  return coverage.covering.length > 0 ? "covered" : "uncovered"
}

export type RegistryVerdict =
  | "idle"
  | "checking"
  | "not-checked"
  | "listed"
  | "not-listed"
  | "subnet-only"

/**
 * `checked: false` is never "not listed". A lookup that did not run and a
 * target that is absent from the registry look identical in a UI that only
 * reads `blocked`, and the difference is exactly what an operator needs.
 */
export function registryVerdict(response: {
  checked?: boolean
  blocked?: boolean
  blocked_subnets?: readonly string[] | null
}): RegistryVerdict {
  if (!response.checked) return "not-checked"
  if (response.blocked) return "listed"
  return (response.blocked_subnets?.length ?? 0) > 0
    ? "subnet-only"
    : "not-listed"
}

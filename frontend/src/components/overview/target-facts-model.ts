import type {
  RoutingTestNfqws,
  RoutingTestNfqwsMatch,
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
  /** Lists that make nfqws act on this target. */
  readonly covering: readonly RoutingTestNfqwsMatch[]
  /** Lists that keep it away from it - the reason coverage does not apply. */
  readonly excluding: readonly RoutingTestNfqwsMatch[]
}

export function summariseNfqwsCoverage(
  nfqws: RoutingTestNfqws | undefined
): NfqwsCoverage {
  if (!nfqws?.available) {
    return { known: false, covering: [], excluding: [] }
  }
  const matches = nfqws.matches ?? []
  return {
    known: true,
    covering: matches.filter((match) => match.includes),
    excluding: matches.filter((match) => !match.includes),
  }
}

/**
 * What to say about nfqws in one line.
 *
 * An exclude match wins the summary even when a covering list also matched,
 * because that is what nfqws does: the exclude list is consulted and the
 * traffic is left alone. Reporting "covered" while nfqws steps aside would be
 * the one reading that sends someone debugging the wrong thing.
 */
export type NfqwsVerdict = "unknown" | "excluded" | "covered" | "uncovered"

export function nfqwsVerdict(coverage: NfqwsCoverage): NfqwsVerdict {
  if (!coverage.known) return "unknown"
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

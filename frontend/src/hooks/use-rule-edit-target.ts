import { useState } from "react"

import {
  resolveRuleEditTargetIndex,
  resolveRuleRouteIndex,
  type RuleWithStableId,
} from "@/lib/rule-route"

export function useRuleEditTarget<T extends RuleWithStableId>(
  rules: readonly T[],
  routeIdentity: string | undefined,
  loaded: boolean,
  equals: (left: T, right: T) => boolean
) {
  const capture = () => {
    const index = loaded ? resolveRuleRouteIndex(rules, routeIdentity) : -1
    return {
      routeIdentity,
      loaded,
      index,
      rule: index >= 0 ? rules[index] : undefined,
    }
  }
  const [session, setSession] = useState(capture)
  let current = session
  if (session.routeIdentity !== routeIdentity || (!session.loaded && loaded)) {
    // Capture once per route, including data that arrives after initial load.
    // The guarded state adjustment happens before children can commit a render
    // with a new URL and the preceding editor's target.
    current = capture()
    setSession(current)
  }
  const index = resolveRuleEditTargetIndex(rules, current.rule, equals)
  return {
    index,
    displayIndex: index >= 0 ? index : current.index,
    // Keep the form mounted with its local draft when the target disappears.
    rule: index >= 0 ? rules[index] : current.rule,
  }
}

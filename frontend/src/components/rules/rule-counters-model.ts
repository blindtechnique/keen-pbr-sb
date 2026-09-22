import type { RuleCountersResponse } from "@/api/generated/model/ruleCountersResponse"

export type RuleCountersState =
  | { status: "idle" | "pending" | "failed" }
  | { status: "ready"; result: RuleCountersResponse }

const object = (value: unknown): value is Record<string, unknown> =>
  value != null && typeof value === "object" && !Array.isArray(value)
const integer = (value: unknown): value is number =>
  typeof value === "number" && Number.isSafeInteger(value) && value >= 0
const uint64 = (value: unknown): value is string =>
  typeof value === "string" &&
  value.length <= 20 &&
  /^(0|[1-9][0-9]*)$/.test(value) &&
  BigInt(value) <= 18446744073709551615n

function evidence(value: unknown, family: "ipv4" | "ipv6"): boolean {
  if (
    !object(value) ||
    !["observed", "unavailable", "ambiguous", "not_applicable"].includes(
      String(value.status)
    ) ||
    value.scope !== "prerouting" ||
    !integer(value.snapshot_at) ||
    !integer(value.total) ||
    typeof value.truncated !== "boolean" ||
    !Array.isArray(value.rules) ||
    value.rules.length > 32 ||
    value.total < value.rules.length ||
    value.truncated !== value.total > value.rules.length
  )
    return false
  if (value.status !== "observed")
    return value.rules.length === 0 && value.total === 0 && !value.truncated
  if (value.rules.length === 0 || value.snapshot_at === 0) return false
  const positions = new Set<string>()
  return value.rules.every((rule: unknown) => {
    if (
      !object(rule) ||
      rule.family !== family ||
      typeof rule.table !== "string" ||
      !rule.table ||
      typeof rule.chain !== "string" ||
      !rule.chain ||
      !integer(rule.position) ||
      rule.position === 0 ||
      !["mark", "drop", "pass"].includes(String(rule.action)) ||
      typeof rule.set_name !== "string" ||
      !uint64(rule.packets) ||
      !uint64(rule.bytes) ||
      [rule.fwmark, rule.fwmask].some(
        (mark) => mark != null && (!integer(mark) || mark > 0xffffffff)
      )
    )
      return false
    const key = JSON.stringify([rule.table, rule.chain, rule.position])
    if (positions.has(key)) return false
    positions.add(key)
    return true
  })
}

// Older or incomplete responses must not render invented zeros or crash the
// rule editor. Decimal strings stay exact; no Number() conversion or summing.
export function isRuleCountersResponse(
  value: unknown
): value is RuleCountersResponse {
  if (
    !object(value) ||
    !integer(value.captured_at) ||
    value.captured_at === 0 ||
    typeof value.unapplied_draft !== "boolean" ||
    !integer(value.total) ||
    typeof value.truncated !== "boolean" ||
    !Array.isArray(value.rules) ||
    value.rules.length > 128 ||
    value.total < value.rules.length ||
    value.truncated !== value.total > value.rules.length
  )
    return false
  return value.rules.every(
    (rule: unknown, index) =>
      object(rule) &&
      rule.rule_index === index &&
      typeof rule.name === "string" &&
      typeof rule.outbound === "string" &&
      typeof rule.outbound_name === "string" &&
      typeof rule.enabled === "boolean" &&
      evidence(rule.ipv4, "ipv4") &&
      evidence(rule.ipv6, "ipv6")
  )
}

export async function runRuleCounters(
  active: { current: AbortController | null },
  request: (signal: AbortSignal) => Promise<unknown>,
  publish: (state: RuleCountersState) => void,
  timeoutMs = 10_000
): Promise<void> {
  if (active.current) return
  const controller = new AbortController()
  active.current = controller
  publish({ status: "pending" })
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const result = await request(controller.signal)
    if (active.current !== controller) return
    publish(
      !controller.signal.aborted && isRuleCountersResponse(result)
        ? { status: "ready", result }
        : { status: "failed" }
    )
  } catch {
    if (active.current === controller) publish({ status: "failed" })
  } finally {
    clearTimeout(timer)
    if (active.current === controller) active.current = null
  }
}

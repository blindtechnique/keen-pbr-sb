import type { DnsConfig } from "@/api/generated/model/dnsConfig"
import { InterceptionState } from "@/api/generated/model/interceptionState"

export function getDnsLearning(dns: DnsConfig | undefined) {
  const legacy = dns?.passive_learning ?? false
  return {
    dns: dns?.learning?.dns ?? legacy,
    l7: dns?.learning?.l7 ?? legacy,
  }
}

export function withDnsLearning(
  dns: DnsConfig | undefined,
  enabled: ReturnType<typeof getDnsLearning>
): DnsConfig {
  const previous = getDnsLearning(dns)
  if (previous.dns === enabled.dns && previous.l7 === enabled.l7)
    return { ...dns }
  return {
    ...dns,
    learning: {
      ...dns?.learning,
      ...(previous.dns !== enabled.dns ? { dns: enabled.dns } : {}),
      ...(previous.l7 !== enabled.l7 ? { l7: enabled.l7 } : {}),
    },
  }
}

/** Older/future daemon fields are unknown, never a failed VPN. */
export function interceptionState(value: unknown): InterceptionState {
  return typeof value === "string" &&
    Object.values(InterceptionState).some((state) => state === value)
    ? (value as InterceptionState)
    : InterceptionState.unknown
}

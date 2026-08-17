export type DnsProbeEvent = {
  type: "DNS"
  domain?: string | null
  source_ip?: string | null
  ecs?: string | null
}

type DnsProbeEventListener = (event: DnsProbeEvent) => void

const listeners = new Set<DnsProbeEventListener>()

export function subscribeDnsProbeEvents(listener: DnsProbeEventListener) {
  listeners.add(listener)
  return () => {
    listeners.delete(listener)
  }
}

export function applyDnsProbeStatusEvent(serialized: string) {
  const event = parseDnsProbeStatusEvent(serialized)
  if (!event) return false

  for (const listener of listeners) listener(event)
  return true
}

function parseDnsProbeStatusEvent(serialized: string): DnsProbeEvent | null {
  try {
    const envelope = JSON.parse(serialized) as {
      type?: unknown
      data?: unknown
    }
    if (
      envelope.type !== "dns_probe" ||
      !envelope.data ||
      typeof envelope.data !== "object"
    ) {
      return null
    }

    const data = envelope.data as Record<string, unknown>
    if (data.type !== "DNS") return null

    return {
      type: "DNS",
      domain: nullableString(data.domain),
      source_ip: nullableString(data.source_ip),
      ecs: nullableString(data.ecs),
    }
  } catch {
    return null
  }
}

function nullableString(value: unknown): string | null | undefined {
  if (value === undefined) return undefined
  if (value === null || typeof value === "string") return value
  return undefined
}

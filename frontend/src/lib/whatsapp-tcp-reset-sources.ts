export const MAX_WHATSAPP_TCP_RESET_SOURCES = 8

type WhatsAppTcpResetDaemon = {
  experimental_whatsapp_tcp_reset_sources?: string[] | null
}

export type WhatsAppTcpResetSourcesIssue =
  | { kind: "duplicate"; value: string }
  | { kind: "invalid"; value: string }
  | { count: number; kind: "too_many" }

export function parseWhatsAppTcpResetSourcesInput(value: string): string[] {
  return value
    .split(/[\s,]+/u)
    .map((item) => item.trim())
    .filter(Boolean)
}

export function getWhatsAppTcpResetSourcesInput(
  daemon: WhatsAppTcpResetDaemon | null | undefined
): string {
  return (daemon?.experimental_whatsapp_tcp_reset_sources ?? []).join("\n")
}

export function getWhatsAppTcpResetSourcesIssue(
  value: string
): WhatsAppTcpResetSourcesIssue | null {
  const sources = parseWhatsAppTcpResetSourcesInput(value)

  if (sources.length > MAX_WHATSAPP_TCP_RESET_SOURCES) {
    return { count: sources.length, kind: "too_many" }
  }

  const seen = new Set<string>()
  for (const source of sources) {
    if (!isExactUnicastIpv4(source)) {
      return { kind: "invalid", value: source }
    }
    if (seen.has(source)) {
      return { kind: "duplicate", value: source }
    }
    seen.add(source)
  }

  return null
}

export function withWhatsAppTcpResetSources<T extends object>(
  daemon: T,
  value: string
): T & { experimental_whatsapp_tcp_reset_sources: string[] } {
  return {
    ...daemon,
    experimental_whatsapp_tcp_reset_sources:
      parseWhatsAppTcpResetSourcesInput(value),
  }
}

function isExactUnicastIpv4(value: string): boolean {
  const octets = value.split(".")
  if (octets.length !== 4) {
    return false
  }

  const parsed = octets.map((octet) => {
    if (!/^(0|[1-9]\d{0,2})$/.test(octet)) {
      return null
    }
    const number = Number(octet)
    return number <= 255 ? number : null
  })

  if (parsed.some((octet) => octet === null)) {
    return false
  }

  const [first, second, third, fourth] = parsed as number[]
  if (
    (first === 0 && second === 0 && third === 0 && fourth === 0) ||
    (first === 255 && second === 255 && third === 255 && fourth === 255)
  ) {
    return false
  }

  return first < 224
}

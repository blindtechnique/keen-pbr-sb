import type { DnsRule } from "@/api/generated/model/dnsRule"
import type { DnsServer } from "@/api/generated/model/dnsServer"

export function getDnsServerDisplayName(server: DnsServer): string {
  return server.display_name?.trim() || server.tag
}

export function createDnsServerDisplayNameMap(
  servers: readonly DnsServer[]
): ReadonlyMap<string, string> {
  return new Map(
    servers.map((server) => [server.tag, getDnsServerDisplayName(server)])
  )
}

export function getDnsServerSearchText(server: DnsServer): string {
  return `${getDnsServerDisplayName(server)} ${server.tag} ${server.address ?? ""}`
}

export function getDnsRuleDisplayName(
  rule: Pick<DnsRule, "display_name"> | undefined,
  index: number
): string {
  return rule?.display_name?.trim() || `DNS ${index + 1}`
}

export function getDnsRuleTechnicalId(
  rule: Pick<DnsRule, "id"> | undefined,
  index: number
): string {
  const stableId = rule?.id?.trim()
  return stableId ? `id:${stableId}` : `index:${index}`
}

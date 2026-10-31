import type { DnsRule } from "@/api/generated/model/dnsRule"

// Keep this aligned with dns_rule_server_tags() on the backend. In particular,
// [] means an empty selection, not permission to revive a legacy server.
export function getDnsRuleServers(
  rule?: Pick<DnsRule, "server" | "servers">
): string[] {
  if (rule?.servers !== undefined) return [...rule.servers]
  return rule?.server !== undefined ? [rule.server] : []
}

export function formatDnsRuleServers(
  rule: Pick<DnsRule, "server" | "servers">,
  names: ReadonlyMap<string, string>
) {
  return getDnsRuleServers(rule)
    .map((tag) => names.get(tag) ?? tag)
    .join(", ")
}

// Preserve the untouched representation for old clients and saved drafts.
// A changed selection is written in the new format, without a stale server.
export function withDnsRuleServers(rule: DnsRule, servers: string[]): DnsRule {
  const previous = getDnsRuleServers(rule)
  if (
    previous.length === servers.length &&
    previous.every((tag, i) => tag === servers[i])
  ) {
    return rule
  }
  const next = { ...rule, servers }
  delete next.server
  return next
}

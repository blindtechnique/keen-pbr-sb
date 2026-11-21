import type { ConfigObject } from "@/api/generated/model/configObject"
import { getDnsRuleServers, withDnsRuleServers } from "@/lib/dns-rule-servers"

export type DnsServerDeleteImpact = {
  matchingRuleIndexes: number[]
  usesFallback: boolean
  usesBootstrap?: boolean
}

export function getDnsServerDeleteReferenceInfo(
  config: ConfigObject,
  serverTags: Iterable<string>
): DnsServerDeleteImpact & {
  matchingRulesCount: number
} {
  const impact = getDnsServerDeleteImpact(config, serverTags)

  return {
    ...impact,
    matchingRulesCount: impact.matchingRuleIndexes.length,
  }
}

export function getDnsServerDeleteImpact(
  config: ConfigObject,
  serverTags: Iterable<string>
): DnsServerDeleteImpact {
  const tagSet = new Set(serverTags)
  const rules = config.dns?.rules ?? []
  const fallback = config.dns?.fallback ?? []

  return {
    matchingRuleIndexes: rules.flatMap((rule, index) =>
      getDnsRuleServers(rule).some((tag) => tagSet.has(tag)) ? [index] : []
    ),
    usesFallback: fallback.some((tag) => tagSet.has(tag)),
    ...(config.dns?.bootstrap?.some((tag) => tagSet.has(tag))
      ? { usesBootstrap: true }
      : {}),
  }
}

export function buildUpdatedConfigForDnsServersDelete(
  config: ConfigObject,
  serverTags: Iterable<string>,
  cleanupReferences: boolean
): ConfigObject {
  const tagSet = new Set(serverTags)
  const dnsConfig = config.dns
  const rules = dnsConfig?.rules ?? []
  const fallback = dnsConfig?.fallback ?? []

  return {
    ...config,
    dns: {
      ...(dnsConfig ?? {}),
      servers: (dnsConfig?.servers ?? []).filter(
        (server) => !tagSet.has(server.tag)
      ),
      rules: cleanupReferences
        ? rules.flatMap((rule) => {
            const selected = getDnsRuleServers(rule)
            if (!selected.some((tag) => tagSet.has(tag))) return [rule]
            const remaining = selected.filter((tag) => !tagSet.has(tag))
            return remaining.length ? [withDnsRuleServers(rule, remaining)] : []
          })
        : rules,
      fallback: cleanupReferences
        ? fallback.filter((tag) => !tagSet.has(tag))
        : fallback,
      ...(dnsConfig?.bootstrap
        ? {
            bootstrap: cleanupReferences
              ? dnsConfig.bootstrap.filter((tag) => !tagSet.has(tag))
              : dnsConfig.bootstrap,
          }
        : {}),
    },
  }
}

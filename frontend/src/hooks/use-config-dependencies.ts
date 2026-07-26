import { useQuery } from "@tanstack/react-query"
import { useMemo } from "react"

import { analyzeConfigDependencies } from "@/api/generated/keen-api"
import type { ConfigObject } from "@/api/generated/model/configObject"
import type { DependencyAnalysisTargetRequest } from "@/api/generated/model/dependencyAnalysisTargetRequest"
import type { DependencyReference } from "@/api/generated/model/dependencyReference"
import type { Dependency } from "@/lib/dependencies"
import {
  createDnsServerDisplayNameMap,
  getDnsRuleDisplayName,
} from "@/lib/dns-display"
import { getListReferenceLabel } from "@/lib/list-display"
import { createOutboundDisplayNameMap } from "@/lib/outbound-display"
import { getRuleEditHref } from "@/lib/rule-route"
import { getRouteRuleDisplayName } from "@/pages/routing-rules-utils"

const MAX_TARGETS_PER_REQUEST = 256

function targetKey(kind: string, id: string) {
  return `${kind}:${id}`
}

function configRelationshipFingerprint(
  config: ConfigObject | undefined,
  targets: DependencyAnalysisTargetRequest[]
) {
  if (!config) return "no-config"
  return JSON.stringify({
    targets,
    outbounds: config.outbounds ?? [],
    lists: Object.fromEntries(
      Object.entries(config.lists ?? {}).map(([name, list]) => [
        name,
        { detour: list.detour, displayName: list.display_name },
      ])
    ),
    route: config.route?.rules ?? [],
    dns: {
      servers: config.dns?.servers ?? [],
      rules: config.dns?.rules ?? [],
      fallback: config.dns?.fallback ?? [],
    },
  })
}

function dependencyLabel(reference: DependencyReference, config: ConfigObject) {
  const index = Number(reference.dependent_id)
  const outboundDisplayNames = createOutboundDisplayNameMap(
    config.outbounds ?? []
  )
  const dnsServerDisplayNames = createDnsServerDisplayNameMap(
    config.dns?.servers ?? []
  )
  switch (reference.dependent_kind) {
    case "routing_rule": {
      const rule = Number.isInteger(index) ? config.route?.rules?.[index] : null
      return rule
        ? `${getRouteRuleDisplayName(rule, index)} → ${
            outboundDisplayNames.get(rule.outbound) ?? rule.outbound
          }`
        : `#${index + 1}`
    }
    case "dns_rule": {
      const rule = Number.isInteger(index) ? config.dns?.rules?.[index] : null
      return rule
        ? `${getDnsRuleDisplayName(rule, index)} → ${
            dnsServerDisplayNames.get(rule.server) ?? rule.server
          }`
        : `DNS ${index + 1}`
    }
    case "outbound_group":
      return (
        outboundDisplayNames.get(reference.dependent_id.split(":")[0] ?? "") ??
        reference.dependent_id.split(":")[0] ??
        reference.dependent_id
      )
    case "list":
      return getListReferenceLabel(reference.dependent_id, config.lists)
    default:
      return reference.dependent_id
  }
}

function dependencyKind(reference: DependencyReference): Dependency["kind"] {
  switch (reference.dependent_kind) {
    case "routing_rule":
      return "routingRule"
    case "dns_rule":
      return "dnsRule"
    case "dns_server":
    case "dns_fallback":
      return "dnsServer"
    case "outbound_group":
      return "failoverGroup"
    case "list":
      return "list"
  }
}

function dependencyHref(
  reference: DependencyReference,
  config: ConfigObject
) {
  const index = Number(reference.dependent_id)
  if (!Number.isInteger(index) || index < 0) {
    return reference.href
  }
  if (reference.dependent_kind === "routing_rule") {
    const rule = config.route?.rules?.[index]
    return rule
      ? getRuleEditHref("routing-rules", rule, index)
      : reference.href
  }
  if (reference.dependent_kind === "dns_rule") {
    const rule = config.dns?.rules?.[index]
    return rule ? getRuleEditHref("dns-rules", rule, index) : reference.href
  }
  return reference.href
}

export function mapDependencyReferences(
  config: ConfigObject,
  references: DependencyReference[]
) {
  const result = new Map<string, Dependency[]>()
  for (const reference of references) {
    const key = targetKey(reference.target.kind, reference.target.id)
    result.set(key, [
      ...(result.get(key) ?? []),
      {
        kind: dependencyKind(reference),
        label: dependencyLabel(reference, config),
        href: dependencyHref(reference, config),
      },
    ])
  }
  return result
}

export function useConfigDependencies(
  config: ConfigObject | undefined,
  targets: DependencyAnalysisTargetRequest[]
) {
  const fingerprint = useMemo(
    () => configRelationshipFingerprint(config, targets),
    [config, targets]
  )
  const query = useQuery({
    queryKey: ["config-dependencies", fingerprint],
    enabled: Boolean(config) && targets.length > 0,
    retry: false,
    staleTime: Number.POSITIVE_INFINITY,
    queryFn: async () => {
      const references: DependencyReference[] = []
      for (
        let offset = 0;
        offset < targets.length;
        offset += MAX_TARGETS_PER_REQUEST
      ) {
        const response = await analyzeConfigDependencies({
          independent: true,
          targets: targets.slice(offset, offset + MAX_TARGETS_PER_REQUEST),
        })
        if (response.status !== 200) {
          throw new Error(response.data.error)
        }
        references.push(...response.data.references)
      }
      return references
    },
  })
  const dependenciesByTarget = useMemo(
    () =>
      config && query.data
        ? mapDependencyReferences(config, query.data)
        : new Map<string, Dependency[]>(),
    [config, query.data]
  )

  return {
    ...query,
    dependenciesByTarget,
    get: (kind: DependencyAnalysisTargetRequest["kind"], id: string) =>
      dependenciesByTarget.get(targetKey(kind, id)) ?? [],
  }
}

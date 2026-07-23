import { useQuery } from "@tanstack/react-query"
import { useMemo } from "react"

import { analyzeConfigDependencies } from "@/api/generated/keen-api"
import type { ConfigObject } from "@/api/generated/model/configObject"
import type { DependencyAnalysisTargetRequest } from "@/api/generated/model/dependencyAnalysisTargetRequest"
import type { DependencyReference } from "@/api/generated/model/dependencyReference"
import type { Dependency } from "@/lib/dependencies"

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
        { detour: list.detour },
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

function dependencyLabel(
  reference: DependencyReference,
  config: ConfigObject
) {
  const index = Number(reference.dependent_id)
  switch (reference.dependent_kind) {
    case "routing_rule": {
      const rule = Number.isInteger(index) ? config.route?.rules?.[index] : null
      return rule ? `#${index + 1} → ${rule.outbound}` : `#${index + 1}`
    }
    case "dns_rule": {
      const rule = Number.isInteger(index) ? config.dns?.rules?.[index] : null
      return rule ? `#${index + 1} → ${rule.server}` : `#${index + 1}`
    }
    case "outbound_group":
      return reference.dependent_id.split(":")[0] ?? reference.dependent_id
    default:
      return reference.dependent_id
  }
}

function dependencyKind(
  reference: DependencyReference
): Dependency["kind"] {
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
        href: reference.href,
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

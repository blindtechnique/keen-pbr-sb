import type { ConfigObject } from "@/api/generated/model/configObject"

export type DependencyKind =
  | "routingRule"
  | "dnsRule"
  | "dnsServer"
  | "failoverGroup"
  | "list"

export type Dependency = {
  kind: DependencyKind
  /** Как эту связь называть человеку: тег, имя списка, номер правила. */
  label: string
  /** Куда вести, если человек захочет посмотреть. */
  href?: string
}

export type BrokenReference = {
  id: string
  label: string
  href: string
}

/** Finds references that can be left behind by a manual edit or import. */
export function findBrokenReferences(
  config: ConfigObject | undefined
): BrokenReference[] {
  if (!config) return []
  const found = new Map<string, BrokenReference>()
  const outbounds = new Set((config.outbounds ?? []).map((item) => item.tag))
  const lists = new Set(Object.keys(config.lists ?? {}))
  const dnsServers = new Set(
    (config.dns?.servers ?? []).map((item) => item.tag).filter(Boolean)
  )
  const add = (item: BrokenReference) => found.set(item.id, item)

  ;(config.route?.rules ?? []).forEach((rule, index) => {
    if (!outbounds.has(rule.outbound)) {
      add({
        id: `route:${index}:outbound:${rule.outbound}`,
        label: `Правило #${index + 1} → ${rule.outbound}`,
        href: `/routing-rules/${index}/edit`,
      })
    }
    for (const list of rule.list ?? []) {
      if (!lists.has(list)) {
        add({
          id: `route:${index}:list:${list}`,
          label: `Правило #${index + 1} → список ${list}`,
          href: `/routing-rules/${index}/edit`,
        })
      }
    }
  })
  ;(config.dns?.rules ?? []).forEach((rule, index) => {
    if (!dnsServers.has(rule.server)) {
      add({
        id: `dns:${index}:server:${rule.server}`,
        label: `DNS-правило #${index + 1} → ${rule.server}`,
        href: `/dns-rules/${index}/edit`,
      })
    }
    for (const list of rule.list ?? []) {
      if (!lists.has(list)) {
        add({
          id: `dns:${index}:list:${list}`,
          label: `DNS-правило #${index + 1} → список ${list}`,
          href: `/dns-rules/${index}/edit`,
        })
      }
    }
  })
  for (const outbound of config.outbounds ?? []) {
    for (const member of (outbound.outbound_groups ?? []).flatMap(
      (group) => group.outbounds
    )) {
      if (!outbounds.has(member)) {
        add({
          id: `outbound:${outbound.tag}:member:${member}`,
          label: `${outbound.tag} → ${member}`,
          href: `/outbounds/${outbound.tag}/edit`,
        })
      }
    }
  }
  for (const [name, list] of Object.entries(config.lists ?? {})) {
    if (list.detour && !outbounds.has(list.detour)) {
      add({
        id: `list:${name}:detour:${list.detour}`,
        label: `Список ${name} → ${list.detour}`,
        href: `/lists/${name}/edit`,
      })
    }
  }
  return [...found.values()]
}

/** Списки, которые перестанут куда-либо направляться вместе с соединением. */
export function listsRoutedThrough(
  config: ConfigObject | undefined,
  tag: string
): string[] {
  const names = new Set<string>()
  for (const rule of config?.route?.rules ?? []) {
    if (rule.outbound !== tag) continue
    for (const name of rule.list ?? []) names.add(name)
  }
  return [...names]
}

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

/**
 * Кто пострадает, если это удалить.
 *
 * Связи в конфигурации существуют давно, но человек узнавал о них в момент
 * удаления — из диалога, который перечислял последствия постфактум. Здесь то
 * же знание считается заранее, чтобы показать его рядом с записью: удаление
 * не должно быть способом выяснить, что от чего зависит.
 *
 * Считается по конфигурации, которая и так лежит на клиенте: ни запросов, ни
 * нового состояния.
 */
export function dependenciesOfList(
  config: ConfigObject | undefined,
  listName: string
): Dependency[] {
  if (!config) return []
  const found: Dependency[] = []

  ;(config.route?.rules ?? []).forEach((rule, index) => {
    if (rule.list?.includes(listName)) {
      found.push({
        kind: "routingRule",
        label: `#${index + 1} → ${rule.outbound}`,
        href: `/routing-rules/${index}/edit`,
      })
    }
  })
  ;(config.dns?.rules ?? []).forEach((rule, index) => {
    if (rule.list?.includes(listName)) {
      found.push({
        kind: "dnsRule",
        label: `#${index + 1} → ${rule.server}`,
        href: `/dns-rules/${index}/edit`,
      })
    }
  })

  return found
}

export function dependenciesOfOutbound(
  config: ConfigObject | undefined,
  tag: string
): Dependency[] {
  if (!config) return []
  const found: Dependency[] = []

  ;(config.route?.rules ?? []).forEach((rule, index) => {
    if (rule.outbound !== tag) return
    found.push({
      kind: "routingRule",
      label:
        rule.list && rule.list.length > 0
          ? `#${index + 1}: ${rule.list.join(", ")}`
          : `#${index + 1}`,
      href: `/routing-rules/${index}/edit`,
    })
  })

  // Группа резервирования, у которой это единственный участник, исчезнет
  // вместе с ним — про такое важно знать до, а не после.
  for (const outbound of config.outbounds ?? []) {
    if (outbound.type !== "urltest") continue
    const members = (outbound.outbound_groups ?? []).flatMap(
      (group) => group.outbounds ?? []
    )
    if (members.includes(tag)) {
      found.push({
        kind: "failoverGroup",
        label: outbound.tag,
        href: `/outbounds/${outbound.tag}/edit`,
      })
    }
  }

  for (const server of config.dns?.servers ?? []) {
    if (server.detour === tag && server.tag) {
      found.push({
        kind: "dnsServer",
        label: server.tag,
        href: `/dns-servers/${encodeURIComponent(server.tag)}/edit`,
      })
    }
  }

  return found
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

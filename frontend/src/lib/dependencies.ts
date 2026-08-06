import type { ConfigObject } from "@/api/generated/model/configObject"
import { getDnsRuleDisplayName } from "@/lib/dns-display"
import { getListReferenceLabel } from "@/lib/list-display"
import {
  createOutboundDisplayNameMap,
  getOutboundDisplayName,
} from "@/lib/outbound-display"
import { getRouteRuleDisplayName } from "@/pages/routing-rules-utils"
import { getRuleEditHref } from "@/lib/rule-route"

export type DependencyKind =
  | "routingRule"
  | "dnsRule"
  | "dnsServer"
  // «DNS:» без слова «правила» — так таблица списков показывает выбранный
  // для списка DNS-сервер (по новой концепции правило — деталь реализации).
  | "dns"
  | "failoverGroup"
  | "listRefresh"
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

export type BrokenReferenceTranslationKey =
  | "missingList"
  | "listDetour"
  | "listRefresh"

export type BrokenReferenceTranslator = Readonly<
  Record<
    BrokenReferenceTranslationKey,
    (values: Readonly<Record<string, string>>) => string
  >
>

/** Finds references that can be left behind by a manual edit or import. */
export function findBrokenReferences(
  config: ConfigObject | undefined,
  translate: BrokenReferenceTranslator
): BrokenReference[] {
  if (!config) return []
  const found = new Map<string, BrokenReference>()
  const outbounds = new Set((config.outbounds ?? []).map((item) => item.tag))
  const outboundDisplayNames = createOutboundDisplayNameMap(
    config.outbounds ?? []
  )
  const lists = new Set(Object.keys(config.lists ?? {}))
  const dnsServers = new Set(
    (config.dns?.servers ?? []).map((item) => item.tag).filter(Boolean)
  )
  const add = (item: BrokenReference) => found.set(item.id, item)

  ;(config.route?.rules ?? []).forEach((rule, index) => {
    if (!outbounds.has(rule.outbound)) {
      add({
        id: `route:${index}:outbound:${rule.outbound}`,
        label: `${getRouteRuleDisplayName(rule, index)} → ${rule.outbound}`,
        href: getRuleEditHref("routing-rules", rule, index),
      })
    }
    for (const list of rule.list ?? []) {
      if (!lists.has(list)) {
        add({
          id: `route:${index}:list:${list}`,
          label: translate.missingList({
            owner: getRouteRuleDisplayName(rule, index),
            target: getListReferenceLabel(list, config.lists),
          }),
          href: getRuleEditHref("routing-rules", rule, index),
        })
      }
    }
  })
  ;(config.dns?.rules ?? []).forEach((rule, index) => {
    if (!dnsServers.has(rule.server)) {
      add({
        id: `dns:${index}:server:${rule.server}`,
        label: `${getDnsRuleDisplayName(rule, index)} → ${rule.server}`,
        href: getRuleEditHref("dns-rules", rule, index),
      })
    }
    for (const list of rule.list ?? []) {
      if (!lists.has(list)) {
        add({
          id: `dns:${index}:list:${list}`,
          label: translate.missingList({
            owner: getDnsRuleDisplayName(rule, index),
            target: getListReferenceLabel(list, config.lists),
          }),
          href: getRuleEditHref("dns-rules", rule, index),
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
          label: `${getOutboundDisplayName(outbound)} → ${
            outboundDisplayNames.get(member) ?? member
          }`,
          href: `/outbounds/${outbound.tag}/edit`,
        })
      }
    }
  }
  for (const [name, list] of Object.entries(config.lists ?? {})) {
    if (list.detour && !outbounds.has(list.detour)) {
      add({
        id: `list:${name}:detour:${list.detour}`,
        label: translate.listDetour({
          list: getListReferenceLabel(name, config.lists),
          target: outboundDisplayNames.get(list.detour) ?? list.detour,
        }),
        href: `/lists/${name}/edit`,
      })
    }
    for (const [index, fallback] of (list.fallback_detours ?? []).entries()) {
      if (outbounds.has(fallback)) continue
      add({
        id: `list:${name}:fallback:${index}:${fallback}`,
        label: translate.listDetour({
          list: getListReferenceLabel(name, config.lists),
          target: outboundDisplayNames.get(fallback) ?? fallback,
        }),
        href: `/lists/${name}/edit`,
      })
    }
  }
  const globalListRefresh = config.list_refresh
  if (globalListRefresh?.detour && !outbounds.has(globalListRefresh.detour)) {
    add({
      id: `list-refresh:detour:${globalListRefresh.detour}`,
      label: translate.listRefresh({
        target:
          outboundDisplayNames.get(globalListRefresh.detour) ??
          globalListRefresh.detour,
      }),
      href: "/general?tab=general",
    })
  }
  for (const [index, fallback] of (
    globalListRefresh?.fallback_detours ?? []
  ).entries()) {
    if (outbounds.has(fallback)) continue
    add({
      id: `list-refresh:fallback:${index}:${fallback}`,
      label: translate.listRefresh({
        target: outboundDisplayNames.get(fallback) ?? fallback,
      }),
      href: "/general?tab=general",
    })
  }
  return [...found.values()]
}

/** Сколько видов связей показывать до того, как список начнёт складываться. */
export const VISIBLE_DEPENDENCY_KINDS = 3

/**
 * Сколько связей одного вида помещается в строку.
 *
 * Ограничения по видам мало: «Списки:» с одиннадцатью именами — формально одна
 * строка, а на экране пять.
 */
export const VISIBLE_DEPENDENCIES_PER_KIND = 3

export type DependencyRow = {
  kind: string
  items: Dependency[]
}

/**
 * Свёрнутый вид «Где используется»: строка на вид связи, не больше трёх строк
 * и не больше трёх имён в строке. Остальное прячется за «Ещё N».
 *
 * Считается именно N связей, а не N видов: «Ещё 11» — это одиннадцать списков,
 * которые сломаются, а «Ещё 2» звучит как две мелочи.
 */
export function planDependencyRows(
  dependencies: Dependency[],
  expanded: boolean
): { rows: DependencyRow[]; hiddenCount: number } {
  const byKind = new Map<string, Dependency[]>()
  for (const dependency of dependencies) {
    byKind.set(dependency.kind, [
      ...(byKind.get(dependency.kind) ?? []),
      dependency,
    ])
  }

  const kinds = [...byKind.entries()]
  const visibleKinds = expanded
    ? kinds
    : kinds.slice(0, VISIBLE_DEPENDENCY_KINDS)
  const rows = visibleKinds.map(([kind, items]) => ({
    kind,
    items: expanded ? items : items.slice(0, VISIBLE_DEPENDENCIES_PER_KIND),
  }))
  const shown = rows.reduce((total, row) => total + row.items.length, 0)

  return { rows, hiddenCount: dependencies.length - shown }
}

import type { ConfigObject } from "@/api/generated/model/configObject"
import type { ListConfig } from "@/api/generated/model/listConfig"
import type { RouteRule } from "@/api/generated/model/routeRule"

// Everything the "route what nfqws2 cannot fix through a tunnel" automation
// needs in the configuration, so that switching it on is one click.
//
// Ticking a box that then refuses to run is not a feature. The automation needs
// three things beyond its own switch: a list to put confirmed hosts in, a file
// for that list to read them from, and a rule sending that list through the
// tunnel the probe measured against. None of them is a decision worth making by
// hand, and the last one is not optional in a subtle way: routing confirmed
// hosts through some *other* outbound would mean the measurement did not
// justify the route.
//
// The daemon deliberately never edits the operator's configuration. Staging
// these three things is therefore the panel's job, and it is done here rather
// than inline so it can be argued with in tests.

export const TUNNEL_PROBE_DEFAULT_LIST = "found_by_probe"
export const TUNNEL_PROBE_RULE_ID = "tunnel_probe"

// List names are constrained to `^[a-z][a-z0-9_]*$`, so a name is always safe
// to put in a path.
export function tunnelProbeListFile(listName: string): string {
  return `/opt/etc/keen-pbr/${listName}.lst`
}

export type TunnelProbeDraft = {
  enabled: boolean
  outbound: string
  list: string
}

export type TunnelProbeProvisioning = {
  config: ConfigObject
  // What was actually settled on, so the form can show it back.
  resolved: TunnelProbeDraft
  createdList: boolean
  addedFile: boolean
  createdRule: boolean
}

// The outbound to default to when none was named: the first one that has an
// interface, because a probe leg is pinned to a device and an outbound with
// only a mark cannot carry one.
function firstProbableOutbound(config: ConfigObject): string {
  for (const outbound of config.outbounds ?? []) {
    if (typeof outbound.interface === "string" && outbound.interface !== "") {
      return outbound.tag
    }
  }
  return ""
}

function ruleMatchesList(rule: RouteRule, listName: string): boolean {
  return Array.isArray(rule.list) && rule.list.includes(listName)
}

function freeRuleId(rules: RouteRule[]): string {
  if (!rules.some((rule) => rule.id === TUNNEL_PROBE_RULE_ID)) {
    return TUNNEL_PROBE_RULE_ID
  }
  for (let suffix = 2; suffix < 100; suffix += 1) {
    const candidate = `${TUNNEL_PROBE_RULE_ID}_${suffix}`
    if (!rules.some((rule) => rule.id === candidate)) return candidate
  }
  // An id is optional; a rule without one is still valid.
  return ""
}

export function provisionTunnelProbe(
  config: ConfigObject,
  draft: TunnelProbeDraft
): TunnelProbeProvisioning {
  const outbound = draft.outbound.trim() || firstProbableOutbound(config)
  const list = draft.list.trim() || TUNNEL_PROBE_DEFAULT_LIST
  const resolved = { enabled: draft.enabled, outbound, list }

  // Switched off: settle the names so the form is not blank next time, but
  // create nothing. Turning something off must not add anything.
  if (!draft.enabled) {
    return {
      config,
      resolved: { ...resolved, outbound: draft.outbound.trim(), list: draft.list.trim() },
      createdList: false,
      addedFile: false,
      createdRule: false,
    }
  }

  // Without an outbound there is nothing to route to, and a rule pointing
  // nowhere would be worse than no rule. The daemon says so in its own words.
  if (outbound === "") {
    return {
      config,
      resolved,
      createdList: false,
      addedFile: false,
      createdRule: false,
    }
  }

  const lists = { ...(config.lists ?? {}) }
  const existing: ListConfig | undefined = lists[list]
  let createdList = false
  let addedFile = false

  if (existing === undefined) {
    lists[list] = {
      display_name: "Найдено пробой",
      file: tunnelProbeListFile(list),
      ttl_ms: 7200000,
    }
    createdList = true
  } else if (typeof existing.file !== "string" || existing.file === "") {
    // An existing list keeps everything it already had - inline domains
    // included, since every source of a list is read together.
    lists[list] = { ...existing, file: tunnelProbeListFile(list) }
    addedFile = true
  }

  const rules = [...(config.route?.rules ?? [])]
  let createdRule = false
  if (!rules.some((rule) => ruleMatchesList(rule, list))) {
    const id = freeRuleId(rules)
    const rule: RouteRule = {
      display_name: "Найдено пробой",
      enabled: true,
      list: [list],
      outbound,
    }
    if (id !== "") rule.id = id
    rules.push(rule)
    createdRule = true
  }

  return {
    config: {
      ...config,
      lists,
      route: { ...config.route, rules },
    },
    resolved,
    createdList,
    addedFile,
    createdRule,
  }
}

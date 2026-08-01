import type { ListConfig } from "@/api/generated/model/listConfig"
import type { ListRefreshConfig } from "@/api/generated/model/listRefreshConfig"
import type { ListRefreshDetourMode } from "@/api/generated/model/listRefreshDetourMode"
import type { Outbound } from "@/api/generated/model/outbound"

export type ListRefreshRouteChain = {
  detour: string
  fallbackDetours: string[]
}

export function getListRefreshCapableOutbounds(
  outbounds: readonly Outbound[]
): Outbound[] {
  return outbounds.filter(
    (outbound) =>
      outbound.type === "interface" ||
      outbound.type === "table" ||
      outbound.type === "urltest"
  )
}

export function getGlobalListRefreshRouteChain(
  config: ListRefreshConfig | undefined
): ListRefreshRouteChain {
  return normalizeListRefreshRouteChain({
    detour: config?.detour ?? "",
    fallbackDetours: config?.fallback_detours ?? [],
  })
}

export function getListRefreshDetourMode(
  list: ListConfig | undefined
): ListRefreshDetourMode {
  if (list?.refresh_detour_mode) {
    return list.refresh_detour_mode
  }

  return list?.detour || (list?.fallback_detours?.length ?? 0) > 0
    ? "override"
    : "inherit"
}

export function getEffectiveListRefreshRouteChain(
  list: ListConfig | undefined,
  globalConfig: ListRefreshConfig | undefined
): ListRefreshRouteChain {
  if (getListRefreshDetourMode(list) === "override") {
    return normalizeListRefreshRouteChain({
      detour: list?.detour ?? "",
      fallbackDetours: list?.fallback_detours ?? [],
    })
  }

  return getGlobalListRefreshRouteChain(globalConfig)
}

export function normalizeListRefreshRouteChain(
  chain: ListRefreshRouteChain
): ListRefreshRouteChain {
  const detour = chain.detour.trim()
  const fallbackDetours = [
    ...new Set(
      chain.fallbackDetours
        .map((fallback) => fallback.trim())
        .filter((fallback) => fallback && fallback !== detour)
    ),
  ]

  return {
    detour,
    fallbackDetours: detour ? fallbackDetours : [],
  }
}

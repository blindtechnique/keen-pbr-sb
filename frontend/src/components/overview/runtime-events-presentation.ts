import type { Outbound } from "@/api/generated/model/outbound"
import type { TransportStatus } from "@/api/generated/model/transportStatus"
import {
  getOutboundDisplayName,
  isSystemDefaultOutbound,
} from "@/lib/outbound-display"

import type { RuntimeEvent } from "./runtime-events-model"

export type PresentedRuntimeEvent = Readonly<{
  id: string
  timestamp: string
  text: string
  tone: "info" | "warning" | "success"
  href: string
}>

type Translate = (key: string, options?: Record<string, unknown>) => string

export function presentRuntimeEvents(
  events: readonly RuntimeEvent[],
  outbounds: readonly Outbound[],
  transports: readonly TransportStatus[],
  t: Translate,
  language: string
): readonly PresentedRuntimeEvent[] {
  const timestamp = new Intl.DateTimeFormat(language, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  })
  const outboundByTag = new Map(
    outbounds.map((outbound) => [outbound.tag, outbound])
  )
  const transportByTag = new Map(
    transports.map((transport) => [transport.tag, transport])
  )
  const outboundName = (tag?: string): string => {
    const outbound = tag ? outboundByTag.get(tag) : undefined
    if (!outbound) return tag || t("overview.runtimeEvents.unknownName")
    if (!outbound.display_name?.trim() && isSystemDefaultOutbound(outbound)) {
      return outbound.tag === "wan"
        ? t("common.systemOutbounds.wan")
        : t("common.systemOutbounds.block")
    }
    return getOutboundDisplayName(outbound)
  }
  const transportName = (tag?: string): string =>
    (tag && transportByTag.get(tag)?.display_name?.trim()) || outboundName(tag)

  return events.map((event): PresentedRuntimeEvent => {
    const base = {
      id: event.id,
      timestamp: timestamp.format(event.observedAt),
    }
    switch (event.kind) {
      case "groupSwitched":
        return {
          ...base,
          text: t("overview.runtimeEvents.groupSwitched", {
            name: outboundName(event.tag),
            from: outboundName(event.from),
            to: outboundName(event.to),
          }),
          tone: "info",
          href: "/?section=routing",
        }
      case "routeDegraded":
        return {
          ...base,
          text: t("overview.runtimeEvents.routeDegraded", {
            name: outboundName(event.tag),
          }),
          tone: "warning",
          href: "/?section=routing",
        }
      case "routeUnavailable":
        return {
          ...base,
          text: t("overview.runtimeEvents.routeUnavailable", {
            name: outboundName(event.tag),
          }),
          tone: "warning",
          href: "/?section=routing",
        }
      case "routeRecovered":
        return {
          ...base,
          text: t("overview.runtimeEvents.routeRecovered", {
            name: outboundName(event.tag),
          }),
          tone: "success",
          href: "/?section=routing",
        }
      case "dnsChanged":
        return {
          ...base,
          text: t("overview.runtimeEvents.dnsChanged"),
          tone: "info",
          href: "/?section=dns",
        }
      case "dnsProblem":
        return {
          ...base,
          text: t("overview.runtimeEvents.dnsProblem"),
          tone: "warning",
          href: "/?section=dns",
        }
      case "dnsRecovered":
        return {
          ...base,
          text: t("overview.runtimeEvents.dnsRecovered"),
          tone: "success",
          href: "/?section=dns",
        }
      case "runtimeFailed":
        return {
          ...base,
          text: t("overview.runtimeEvents.runtimeFailed"),
          tone: "warning",
          href: "/?section=service",
        }
      case "runtimeRecovered":
        return {
          ...base,
          text: t("overview.runtimeEvents.runtimeRecovered"),
          tone: "success",
          href: "/?section=service",
        }
      case "serviceRestarted":
        return {
          ...base,
          text: t("overview.runtimeEvents.serviceRestarted"),
          tone: "info",
          href: "/?section=service",
        }
      case "transportUnavailable":
        return {
          ...base,
          text: t("overview.runtimeEvents.transportUnavailable", {
            name: transportName(event.tag),
          }),
          tone: "warning",
          href: "/?section=service",
        }
      case "transportRecovered":
        return {
          ...base,
          text: t("overview.runtimeEvents.transportRecovered", {
            name: transportName(event.tag),
          }),
          tone: "success",
          href: "/?section=service",
        }
      case "transportRestarted":
        return {
          ...base,
          text: t("overview.runtimeEvents.transportRestarted", {
            name: transportName(event.tag),
          }),
          tone: "info",
          href: "/?section=service",
        }
    }
  })
}

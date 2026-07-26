import { useTranslation } from "react-i18next"

import type {
  Outbound,
  RouteRule,
  RuntimeInterfaceInventoryEntry,
  RuntimeOutboundState,
} from "@/api/generated/model"
import { collectActiveTrafficPaths } from "@/components/overview/active-interface-traffic-model"
import { InterfaceTraffic } from "@/components/transports/interface-traffic"
import { Badge } from "@/components/ui/badge"
import { useInterfaceProtocols } from "@/hooks/use-interface-protocols"

export function ActiveInterfaceTraffic({
  outbounds,
  rules,
  runtimeByTag,
  runtimeInterfaceByName,
}: {
  readonly outbounds: readonly Outbound[]
  readonly rules: readonly RouteRule[]
  readonly runtimeByTag: ReadonlyMap<string, RuntimeOutboundState>
  readonly runtimeInterfaceByName: ReadonlyMap<
    string,
    RuntimeInterfaceInventoryEntry
  >
}) {
  const { i18n, t } = useTranslation()
  const { protocolOf } = useInterfaceProtocols()
  const paths = collectActiveTrafficPaths(outbounds, rules, runtimeByTag).filter(
    (path) => runtimeInterfaceByName.get(path.interfaceName)?.traffic
  )

  if (paths.length === 0) {
    return null
  }

  return (
    <div className="mt-3 border-t pt-3">
      <div className="mb-2 text-xs font-semibold tracking-wide text-muted-foreground uppercase">
        {t("overview.outbounds.liveTraffic")}
      </div>
      <div className="grid gap-3 lg:grid-cols-2">
        {paths.map((path) => {
          const protocol = protocolOf(path.interfaceName)
          return (
            <div className="min-w-0" key={path.interfaceName}>
              <div className="flex min-w-0 items-center gap-2">
                <span className="truncate text-sm font-medium">
                  {path.label}
                </span>
                {protocol ? (
                  <Badge
                    className="shrink-0 font-mono text-[10px]"
                    size="xs"
                    variant="outline"
                  >
                    {protocol}
                  </Badge>
                ) : null}
              </div>
              <InterfaceTraffic
                className="mt-1"
                labels={{
                  receive: t("transports.traffic.receive"),
                  transmit: t("transports.traffic.transmit"),
                  received: t("transports.traffic.received"),
                  transmitted: t("transports.traffic.transmitted"),
                  chart: t("transports.traffic.chart"),
                }}
                locale={i18n.resolvedLanguage ?? i18n.language}
                traffic={
                  runtimeInterfaceByName.get(path.interfaceName)?.traffic
                }
              />
            </div>
          )
        })}
      </div>
    </div>
  )
}

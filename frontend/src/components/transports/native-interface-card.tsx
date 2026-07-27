import {
  ChevronDownIcon,
  EyeIcon,
  EyeOffIcon,
  WorkflowIcon,
} from "lucide-react"
import { useTranslation } from "react-i18next"

import type { NdmsManagementBlocker } from "@/api/generated/model"
import { KeeneticStatus } from "@/components/shared/keenetic-status"
import { TransportProtocolIcon } from "@/components/transports/protocol-icon"
import { InterfaceTraffic } from "@/components/transports/interface-traffic"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardAction,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  getNativeRouteActionability,
  type NativeInterfaceModel,
  type NativeRouteBlockReason,
} from "@/lib/native-interfaces"

export function NativeInterfaceCard({
  nativeInterface,
  latencyMs,
  boundOutboundTag,
  hasConfig,
  expanded,
  hidden,
  onCreateRoute,
  onExpandedChange,
  onHiddenChange,
}: {
  readonly nativeInterface: NativeInterfaceModel
  readonly latencyMs?: number
  readonly boundOutboundTag?: string
  readonly hasConfig: boolean
  readonly expanded: boolean
  readonly hidden: boolean
  readonly onCreateRoute: (interfaceName: string) => void
  readonly onExpandedChange: (expanded: boolean) => void
  readonly onHiddenChange: (hidden: boolean) => void
}) {
  const { t, i18n } = useTranslation()
  const actionability = getNativeRouteActionability(nativeInterface, {
    hasConfig,
    boundOutboundTag,
  })
  const visibleLatency =
    typeof latencyMs === "number" &&
    Number.isFinite(latencyMs) &&
    latencyMs >= 0
      ? latencyMs
      : undefined
  const managementReadiness = nativeInterface.source.management_readiness

  return (
    <Card className="flex h-full min-w-0 flex-col overflow-hidden" size="sm">
      <CardHeader className="min-w-0">
        <div className="min-w-0">
          <CardTitle className="leading-5 tracking-normal break-words">
            {nativeInterface.label}
          </CardTitle>
          <div className="mt-1 flex min-w-0 flex-wrap items-center gap-1.5">
            <TransportProtocolIcon protocol={nativeInterface.protocol.label} />
            <Badge size="xs" variant="secondary">
              {t("transports.nativeInterface.keeneticOwner")}
            </Badge>
            <span
              className="truncate font-mono text-xs text-muted-foreground"
              title={nativeInterface.logicalName}
            >
              {nativeInterface.logicalName}
            </span>
          </div>
        </div>
        <CardAction className="flex items-center gap-1">
          <KeeneticStatus tone={nativeInterface.live ? "success" : "neutral"}>
            {nativeInterface.runtime
              ? nativeInterface.live
                ? t("transports.nativeInterface.connected")
                : t("transports.nativeInterface.disconnected")
              : t("transports.nativeInterface.liveUnavailable")}
          </KeeneticStatus>
          <Button
            aria-expanded={expanded}
            aria-label={
              expanded
                ? t("transports.details.hide")
                : t("transports.details.show")
            }
            className="size-7"
            onClick={() => onExpandedChange(!expanded)}
            size="icon"
            title={
              expanded
                ? t("transports.details.hide")
                : t("transports.details.show")
            }
            variant="ghost"
          >
            <ChevronDownIcon
              className={`size-4 transition-transform ${expanded ? "rotate-180" : ""}`}
            />
          </Button>
        </CardAction>
      </CardHeader>

      <CardContent
        className={`flex min-w-0 flex-1 flex-col gap-1.5 text-sm ${
          expanded ? "" : "hidden"
        }`}
      >
        {expanded ? (
          <>
            <NativeInterfaceField
              label={t("transports.nativeInterface.kernelName")}
              mono
              value={
                nativeInterface.kernelName ??
                t("transports.nativeInterface.unresolved")
              }
            />
            {visibleLatency !== undefined ? (
              <NativeInterfaceField
                label={t("transports.nativeInterface.latency")}
                value={t("transports.latencyValue", { value: visibleLatency })}
              />
            ) : null}
            <NativeInterfaceField
              label={t("transports.nativeInterface.boundRoute")}
              mono={Boolean(boundOutboundTag)}
              value={
                boundOutboundTag ??
                t("transports.nativeInterface.routeNotConfigured")
              }
            />
            <InterfaceTraffic
              labels={{
                receive: t("transports.traffic.receive"),
                transmit: t("transports.traffic.transmit"),
                received: t("transports.traffic.received"),
                transmitted: t("transports.traffic.transmitted"),
                chart: t("transports.traffic.chart"),
              }}
              locale={i18n.resolvedLanguage ?? i18n.language}
              showChart={false}
              traffic={nativeInterface.runtime?.traffic}
            />

            <div className="my-1 border-t" />
            <NativeInterfaceField
              label={t("transports.nativeInterface.logicalName")}
              mono
              value={
                nativeInterface.logicalName ||
                t("transports.nativeInterface.unknown")
              }
            />
            <NativeInterfaceField
              label={t("transports.nativeInterface.protocol")}
              value={nativeInterface.protocol.label}
            />
            <NativeInterfaceField
              label={t("transports.nativeInterface.role")}
              value={roleLabel(nativeInterface.source.role, t)}
            />
            <NativeInterfaceField
              label={t("transports.nativeInterface.liveState")}
              value={
                nativeInterface.runtime
                  ? nativeInterface.live
                    ? t("transports.nativeInterface.liveUp")
                    : t("transports.nativeInterface.liveDown")
                  : t("transports.nativeInterface.liveUnavailable")
              }
            />
            <NativeInterfaceField
              label={t("transports.nativeInterface.connectedState")}
              value={booleanState(
                nativeInterface.connected,
                t("transports.nativeInterface.connected"),
                t("transports.nativeInterface.disconnected"),
                t("transports.nativeInterface.unknown")
              )}
            />
            <NativeInterfaceField
              label={t("transports.nativeInterface.linkState")}
              value={booleanState(
                nativeInterface.link,
                t("transports.nativeInterface.linkUp"),
                t("transports.nativeInterface.linkDown"),
                t("transports.nativeInterface.unknown")
              )}
            />
            <NativeInterfaceField
              label={t("transports.nativeInterface.management")}
              title={managementReadinessTitle(managementReadiness?.blockers, t)}
              value={
                !managementReadiness || managementReadiness.candidate
                  ? t("transports.nativeInterface.managementReadOnly")
                  : t("transports.nativeInterface.managementUnsupported")
              }
            />

            <div className="mt-2 flex min-w-0 flex-wrap items-center gap-2 border-t pt-3">
              <Button
                disabled={!actionability.enabled}
                onClick={() => {
                  if (actionability.enabled) {
                    onCreateRoute(actionability.interfaceName)
                  }
                }}
                size="sm"
                title={
                  actionability.enabled
                    ? t("transports.routing.bindOutbound")
                    : routeBlockTitle(actionability.reason, boundOutboundTag, t)
                }
                variant="outline"
              >
                <WorkflowIcon />
                {t("transports.routing.bindOutbound")}
              </Button>
              <Button
                className="ml-auto"
                onClick={() => onHiddenChange(!hidden)}
                size="sm"
                variant="ghost"
              >
                {hidden ? <EyeIcon /> : <EyeOffIcon />}
                {hidden
                  ? t("transports.nativeInterface.restore")
                  : t("transports.nativeInterface.hide")}
              </Button>
            </div>
          </>
        ) : null}
      </CardContent>
    </Card>
  )
}

function NativeInterfaceField({
  label,
  value,
  mono = false,
  title,
}: {
  readonly label: string
  readonly value: string
  readonly mono?: boolean
  readonly title?: string
}) {
  return (
    <div className="grid min-w-0 grid-cols-[auto_minmax(0,1fr)] items-baseline gap-4">
      <span className="min-w-0 whitespace-nowrap text-muted-foreground">
        {label}
      </span>
      <span
        className={`min-w-0 truncate text-right ${mono ? "font-mono" : ""}`}
        title={title ?? value}
      >
        {value}
      </span>
    </div>
  )
}

function managementReadinessTitle(
  blockers: readonly NdmsManagementBlocker[] | undefined,
  t: (key: string) => string
): string {
  if (!blockers) {
    return t("transports.nativeInterface.managementReadinessUnavailable")
  }
  if (blockers.length === 0) {
    return t("transports.nativeInterface.managementReady")
  }
  return blockers
    .map((blocker) =>
      t(`transports.nativeInterface.managementBlockers.${blocker}`)
    )
    .join("; ")
}

function booleanState(
  value: boolean | undefined,
  whenTrue: string,
  whenFalse: string,
  unknown: string
): string {
  if (value === undefined) {
    return unknown
  }
  return value ? whenTrue : whenFalse
}

function routeBlockTitle(
  reason: NativeRouteBlockReason,
  boundOutboundTag: string | undefined,
  t: (key: string, options?: Record<string, unknown>) => string
): string {
  switch (reason) {
    case "not-client":
      return t("transports.nativeInterface.routeNotClient")
    case "unresolved":
      return t("transports.nativeInterface.routeUnresolved")
    case "not-live":
      return t("transports.nativeInterface.routeNotLive")
    case "already-bound":
      return t("transports.routing.alreadyBound", {
        tag: boundOutboundTag ?? "",
      })
    case "no-config":
      return t("transports.nativeInterface.routeConfigUnavailable")
  }
}

function roleLabel(
  role: NativeInterfaceModel["source"]["role"],
  t: (key: string) => string
): string {
  switch (role) {
    case "client":
      return t("transports.nativeInterface.roleClient")
    case "server":
      return t("transports.nativeInterface.roleServer")
    case "unknown":
      return t("transports.nativeInterface.roleUnknown")
  }
}

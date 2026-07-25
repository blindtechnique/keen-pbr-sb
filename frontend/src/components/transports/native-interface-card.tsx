import { WorkflowIcon } from "lucide-react"
import { useTranslation } from "react-i18next"

import { KeeneticStatus } from "@/components/shared/keenetic-status"
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
  onCreateRoute,
}: {
  readonly nativeInterface: NativeInterfaceModel
  readonly latencyMs?: number
  readonly boundOutboundTag?: string
  readonly hasConfig: boolean
  readonly onCreateRoute: (interfaceName: string) => void
}) {
  const { t } = useTranslation()
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

  return (
    <Card className="flex h-full min-w-0 flex-col overflow-hidden">
      <CardHeader className="min-w-0">
        <div className="min-w-0">
          <CardTitle className="truncate">{nativeInterface.label}</CardTitle>
          <div className="mt-1 flex min-w-0 flex-wrap items-center gap-1.5">
            <Badge size="xs" variant="outline">
              {nativeInterface.protocol}
            </Badge>
            <Badge size="xs" variant="secondary">
              {t("transports.nativeInterface.keeneticOwner")}
            </Badge>
          </div>
        </div>
        <CardAction>
          <KeeneticStatus tone={nativeInterface.live ? "success" : "neutral"}>
            {nativeInterface.runtime
              ? nativeInterface.live
                ? t("transports.nativeInterface.liveUp")
                : t("transports.nativeInterface.liveDown")
              : t("transports.nativeInterface.liveUnavailable")}
          </KeeneticStatus>
        </CardAction>
      </CardHeader>

      <CardContent className="flex min-w-0 flex-1 flex-col gap-1.5 text-sm">
        <NativeInterfaceField
          label={t("transports.nativeInterface.logicalName")}
          mono
          value={
            nativeInterface.logicalName ||
            t("transports.nativeInterface.unknown")
          }
        />
        <NativeInterfaceField
          label={t("transports.nativeInterface.kernelName")}
          mono
          value={
            nativeInterface.kernelName ??
            t("transports.nativeInterface.unresolved")
          }
        />
        <NativeInterfaceField
          label={t("transports.nativeInterface.protocol")}
          value={nativeInterface.protocol}
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

        <div className="mt-auto border-t pt-3">
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
        </div>
      </CardContent>
    </Card>
  )
}

function NativeInterfaceField({
  label,
  value,
  mono = false,
}: {
  readonly label: string
  readonly value: string
  readonly mono?: boolean
}) {
  return (
    <div className="grid min-w-0 grid-cols-[auto_minmax(0,1fr)] items-baseline gap-4">
      <span className="min-w-0 whitespace-nowrap text-muted-foreground">
        {label}
      </span>
      <span
        className={`min-w-0 truncate text-right ${mono ? "font-mono" : ""}`}
        title={value}
      >
        {value}
      </span>
    </div>
  )
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

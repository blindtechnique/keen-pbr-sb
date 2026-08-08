import { EyeIcon, EyeOffIcon, WorkflowIcon } from "lucide-react"
import type { ReactNode } from "react"
import { useTranslation } from "react-i18next"

import type { NdmsManagementBlocker } from "@/api/generated/model"
import { InterfaceTraffic } from "@/components/transports/interface-traffic"
import { Button } from "@/components/ui/button"
import {
  getNativeRouteActionability,
  type NativeInterfaceModel,
  type NativeRouteBlockReason,
} from "@/lib/native-interfaces"

/**
 * Подробности интерфейса KeeneticOS — то, что раньше жило в раскрытой карточке.
 *
 * Список стал таблицей, и всё, что не помещается в строку, встаёт под ней во
 * всю ширину. Поля идут в две колонки: в одну они растягивались на всю ширину
 * таблицы, и подпись оказывалась в сантиметрах от значения.
 */
export function NativeInterfaceDetails({
  nativeInterface,
  boundOutboundTag,
  hasConfig,
  hidden,
  onCreateRoute,
  onHiddenChange,
  usage,
}: {
  readonly nativeInterface: NativeInterfaceModel
  readonly boundOutboundTag?: string
  readonly hasConfig: boolean
  readonly hidden: boolean
  readonly onCreateRoute: (interfaceName: string) => void
  readonly onHiddenChange: (hidden: boolean) => void
  /** «Кто этим пользуется» — тот же блок категорий, что у своих туннелей. */
  readonly usage?: ReactNode
}) {
  const { t, i18n } = useTranslation()
  const actionability = getNativeRouteActionability(nativeInterface, {
    hasConfig,
    boundOutboundTag,
  })
  const managementReadiness = nativeInterface.source.management_readiness

  return (
    <div className="space-y-3 text-sm">
      <div className="grid min-w-0 gap-x-8 gap-y-1.5 sm:grid-cols-2">
        <NativeInterfaceField
          label={t("transports.nativeInterface.kernelName")}
          mono
          value={
            nativeInterface.kernelName ??
            t("transports.nativeInterface.unresolved")
          }
        />
        <NativeInterfaceField
          label={t("transports.nativeInterface.boundRoute")}
          mono={Boolean(boundOutboundTag)}
          value={
            boundOutboundTag ??
            t("transports.nativeInterface.routeNotConfigured")
          }
        />
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
      </div>

      <InterfaceTraffic
        labels={{
          receive: t("transports.traffic.receive"),
          transmit: t("transports.traffic.transmit"),
          received: t("transports.traffic.received"),
          transmitted: t("transports.traffic.transmitted"),
          chart: t("transports.traffic.chart"),
          noTraffic: t("transports.traffic.noTraffic"),
        }}
        locale={i18n.resolvedLanguage ?? i18n.language}
        showChart={false}
        traffic={nativeInterface.runtime?.traffic}
      />

      {usage}

      <div className="flex min-w-0 flex-wrap items-center gap-2">
        <Button
          disabled={!actionability.enabled}
          onClick={() => {
            if (actionability.enabled) {
              onCreateRoute(actionability.interfaceName)
            }
          }}
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
        <Button onClick={() => onHiddenChange(!hidden)} variant="outline">
          {hidden ? <EyeIcon /> : <EyeOffIcon />}
          {hidden
            ? t("transports.nativeInterface.restore")
            : t("transports.nativeInterface.hide")}
        </Button>
      </div>
    </div>
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
    <div className="grid min-w-0 grid-cols-[minmax(0,9rem)_minmax(0,1fr)] items-baseline gap-3">
      <span className="min-w-0 truncate text-muted-foreground" title={label}>
        {label}
      </span>
      <span
        className={`min-w-0 truncate ${mono ? "font-mono" : ""}`}
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

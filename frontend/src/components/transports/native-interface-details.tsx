import { TransportExitCheckButton } from "@/components/transports/exit-check-button"
import {
  AlertTriangleIcon,
  EyeIcon,
  EyeOffIcon,
  WorkflowIcon,
} from "lucide-react"
import type { ReactNode } from "react"
import { useTranslation } from "react-i18next"

import type {
  NdmsNativeInventoryDeleteBlocker,
  NdmsNativeInventoryOwnershipState,
  NdmsNativeOwnershipLifecycle,
  RuntimeInterfaceUptimeSource,
} from "@/api/generated/model"
import { InterfaceTraffic } from "@/components/transports/interface-traffic"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import {
  getNativeRouteActionability,
  type NativeInterfaceModel,
  type NativeRouteBlockReason,
} from "@/lib/native-interfaces"
import { routerNowMs } from "@/api/router-clock"
import { useVisibleTick } from "@/hooks/use-visible-tick"
import { formatUptimeSince } from "@/lib/uptime-format"

// The uptime is rendered as a running clock, so it needs a reason to re-render
// every second. useVisibleTick stops while the tab is hidden, so an unattended
// page does not burn a render per second forever.
const UPTIME_TICK_MS = 1_000

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
  // Drives the running uptime clock; the value itself is read below.
  useVisibleTick(UPTIME_TICK_MS)
  const actionability = getNativeRouteActionability(nativeInterface, {
    hasConfig,
    boundOutboundTag,
  })
  const mutation = nativeInterface.source.native_mutation
  const deleteEnabled =
    mutation.delete_candidate && Boolean(mutation.ownership_revision)
  const lifecycleAvailable =
    (nativeInterface.source.kind === "wireguard" ||
      nativeInterface.source.kind === "amnezia_wireguard") &&
    nativeInterface.source.role !== "server"

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
          label={t("transports.nativeInterface.uptime")}
          title={uptimeSourceTitle(
            nativeInterface.runtime?.link_uptime_source,
            t
          )}
          value={formatUptimeSince(
            nativeInterface.runtime?.link_up_since_unix_ms,
            t,
            routerNowMs()
          )}
        />
        <NativeInterfaceField
          label={t("transports.nativeInterface.management")}
          value={
            lifecycleAvailable
              ? t("transports.nativeInterface.managementLifecycle")
              : t("transports.nativeInterface.managementUnsupported")
          }
        />
        <NativeInterfaceField
          label={t("transports.nativeMutation.ownershipLabel")}
          value={ownershipLabel(mutation.ownership_state, t)}
        />
        <NativeInterfaceField
          label={t("transports.nativeMutation.deleteReadinessLabel")}
          value={
            deleteEnabled
              ? t("transports.nativeMutation.deleteReady")
              : t("transports.nativeMutation.deleteUnavailable")
          }
        />
      </div>

      {mutation.delete_blockers.length > 0 ? (
        <div className="space-y-1 rounded-md bg-muted/50 p-3 text-xs text-muted-foreground">
          <p className="font-medium break-words text-foreground">
            {t("transports.nativeMutation.deleteBlockersTitle")}
          </p>
          <ul className="list-disc space-y-1 pl-5">
            {mutation.delete_blockers.map((blocker) => (
              <li className="break-words" key={blocker}>
                {deleteBlockerLabel(blocker, t)}
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {mutation.ownership_lifecycle === "active_save_acknowledged_unverified" ||
      mutation.ownership_lifecycle ===
        "deleted_save_acknowledged_unverified" ? (
        <Alert variant="warning">
          <AlertTriangleIcon />
          <AlertTitle>
            {t("transports.nativeMutation.unverifiedSave.title")}
          </AlertTitle>
          <AlertDescription className="break-words">
            {ownershipLifecycleDescription(mutation.ownership_lifecycle, t)}
          </AlertDescription>
        </Alert>
      ) : null}

      <InterfaceTraffic
        labels={{
          receive: t("transports.traffic.receive"),
          transmit: t("transports.traffic.transmit"),
          received: t("transports.traffic.received"),
          transmitted: t("transports.traffic.transmitted"),
          chart: t("transports.traffic.chart"),
          noTraffic: t("transports.traffic.noTraffic"),
          stale: t("transports.traffic.stale"),
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
        {/* Последней в ряду, как и у своих туннелей. Работает и без маршрута
            keen-pbr: у нативного его обычно нет, а измерение делает
            атрибутируемым привязка к устройству, а не метка. Имя берётся
            ядерное — привязаться можно только к тому, что в ядре есть, и
            mapNativeInterfaces намеренно не подставляет сюда логическое. */}
        <TransportExitCheckButton
          device={boundOutboundTag ? undefined : nativeInterface.kernelName}
          outbound={boundOutboundTag ?? undefined}
        />
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

function ownershipLabel(
  state: NdmsNativeInventoryOwnershipState,
  t: (key: string) => string
): string {
  switch (state) {
    case "not_applicable":
      return t("transports.nativeMutation.ownership.not_applicable")
    case "foreign":
      return t("transports.nativeMutation.ownership.foreign")
    case "panel_owned_active":
      return t("transports.nativeMutation.ownership.panel_owned_active")
    case "panel_owned_tombstone":
      return t("transports.nativeMutation.ownership.panel_owned_tombstone")
    case "unavailable":
      return t("transports.nativeMutation.ownership.unavailable")
  }
}

function deleteBlockerLabel(
  blocker: NdmsNativeInventoryDeleteBlocker,
  t: (key: string) => string
): string {
  switch (blocker) {
    case "unsupported_kind":
      return t("transports.nativeMutation.blockers.unsupported_kind")
    case "invalid_or_protected_target":
      return t("transports.nativeMutation.blockers.invalid_or_protected_target")
    case "catalog_not_fresh":
      return t("transports.nativeMutation.blockers.catalog_not_fresh")
    case "ownership_inventory_unavailable":
      return t(
        "transports.nativeMutation.blockers.ownership_inventory_unavailable"
      )
    case "ownership_absent":
      return t("transports.nativeMutation.blockers.ownership_absent")
    case "ownership_not_active":
      return t("transports.nativeMutation.blockers.ownership_not_active")
    case "ownership_kind_mismatch":
      return t("transports.nativeMutation.blockers.ownership_kind_mismatch")
    case "import_journal_not_authoritatively_clean":
      return t(
        "transports.nativeMutation.blockers.import_journal_not_authoritatively_clean"
      )
    case "import_recovery_required":
      return t("transports.nativeMutation.blockers.import_recovery_required")
    case "import_journal_unsafe":
      return t("transports.nativeMutation.blockers.import_journal_unsafe")
    case "import_journal_unavailable":
      return t("transports.nativeMutation.blockers.import_journal_unavailable")
    case "delete_recovery_required":
      return t("transports.nativeMutation.blockers.delete_recovery_required")
    case "delete_journal_unsafe":
      return t("transports.nativeMutation.blockers.delete_journal_unsafe")
  }
}

function ownershipLifecycleDescription(
  lifecycle: NdmsNativeOwnershipLifecycle,
  t: (key: string) => string
): string {
  switch (lifecycle) {
    case "active_save_acknowledged_unverified":
      return t(
        "transports.nativeMutation.unverifiedSave.active_save_acknowledged_unverified"
      )
    case "deleted_save_acknowledged_unverified":
      return t(
        "transports.nativeMutation.unverifiedSave.deleted_save_acknowledged_unverified"
      )
    case "active_running_only":
      return ""
  }
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

/**
 * Explains, on hover, how much the shown uptime is worth.
 *
 * The two sources are not interchangeable: a firmware-anchored value outlives
 * a keen-pbr restart, an observed one does not. Hiding that difference would
 * leave a reader unable to tell a genuinely short uptime from an anchor this
 * daemon simply lost.
 */
function uptimeSourceTitle(
  source: RuntimeInterfaceUptimeSource | undefined,
  t: (key: string) => string
): string | undefined {
  if (source === "firmware") {
    return t("transports.nativeInterface.uptimeFromFirmware")
  }
  if (source === "observed") {
    return t("transports.nativeInterface.uptimeObserved")
  }
  return undefined
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

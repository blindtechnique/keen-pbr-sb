import { useMemo, useState } from "react"
import { useTranslation } from "react-i18next"
import { Download, WandSparklesIcon } from "lucide-react"
import { useLocation } from "wouter"

import type { ApiError } from "@/api/client"

import type { DnsCheckStatus } from "@/hooks/use-dns-check"
import {
  useGetConfig,
  useGetHealthRouting,
  useGetHealthService,
  useGetRuntimeInterfaces,
  useGetRuntimeOutbounds,
  useGetTransports,
} from "@/api/queries"
import { selectConfig } from "@/api/selectors"
import { Button } from "@/components/ui/button"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { ListPlaceholder } from "@/components/shared/list-placeholder"
import { TableSkeleton } from "@/components/shared/table-skeleton"
import { SectionCard } from "@/components/shared/section-card"
import { RoutingHealthCard } from "@/components/overview/routing-health-card"
import { DnsCheckWidget } from "@/components/overview/dns-check-widget"
import { OutboundStateList } from "@/components/overview/outbound-state-list"
import { RouteTrafficShareCard } from "@/components/overview/route-traffic-share-card"
import { ServicesStatusCard } from "@/components/overview/services-status-card"
import { RouterInfoPanel } from "@/components/overview/router-info-card"
import { DiagnosticsDownloadDialog } from "@/components/overview/diagnostics-download-dialog"
import { RoutingTestPanel } from "@/components/overview/routing-test-panel"
import { SystemStatusSummary } from "@/components/overview/system-status-summary"
import { ActiveInterfaceTraffic } from "@/components/overview/active-interface-traffic"
import { selectDashboardRuntimeOutbounds } from "@/components/overview/dashboard-outbound-relevance"
import { dashboardSectionIds } from "@/components/overview/system-status-summary-model"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { getApiErrorMessage } from "@/lib/api-errors"

export function OverviewPage() {
  const { t } = useTranslation()
  const [, navigate] = useLocation()
  const [dnsCheckStatus, setDnsCheckStatus] = useState<DnsCheckStatus>("idle")
  const [isDiagnosticsDialogOpen, setIsDiagnosticsDialogOpen] = useState(false)
  const serviceHealthQuery = useGetHealthService()
  const configQuery = useGetConfig()
  const routingHealthQuery = useGetHealthRouting({
    query: {
      refetchInterval: 45_000,
      refetchIntervalInBackground: false,
    },
  })
  const runtimeInterfacesQuery = useGetRuntimeInterfaces()
  const runtimeOutboundsQuery = useGetRuntimeOutbounds()
  // ServicesStatusCard observes the same query with its existing refresh
  // policy. This observer only consumes that shared cache for connected-since
  // timestamps; it does not add another polling loop.
  const transportsQuery = useGetTransports()

  const serviceHealth =
    serviceHealthQuery.data?.status === 200
      ? serviceHealthQuery.data.data
      : undefined
  const loadedConfig = selectConfig(configQuery.data)
  const configIsDraft =
    configQuery.data?.status === 200 ? configQuery.data.data.is_draft : false
  const routingHealth =
    routingHealthQuery.data?.status === 200
      ? routingHealthQuery.data.data
      : undefined
  const runtimeOutbounds = useMemo(
    () =>
      runtimeOutboundsQuery.data?.status === 200
        ? runtimeOutboundsQuery.data.data.outbounds
        : [],
    [runtimeOutboundsQuery.data]
  )
  const transportStatuses = useMemo(
    () =>
      transportsQuery.data?.status === 200
        ? transportsQuery.data.data
        : undefined,
    [transportsQuery.data]
  )
  const dashboardRuntimeOutbounds = useMemo(
    () =>
      selectDashboardRuntimeOutbounds({
        runtimeOutbounds,
        transports: transportStatuses,
      }),
    [runtimeOutbounds, transportStatuses]
  )
  const runtimeOutboundByTag = useMemo(
    () =>
      new Map(
        dashboardRuntimeOutbounds.map((runtimeOutbound) => [
          runtimeOutbound.tag,
          runtimeOutbound,
        ])
      ),
    [dashboardRuntimeOutbounds]
  )
  const runtimeInterfaceByName = useMemo(
    () =>
      new Map(
        (runtimeInterfacesQuery.data?.status === 200
          ? runtimeInterfacesQuery.data.data.interfaces
          : []
        ).map((runtimeInterface) => [runtimeInterface.name, runtimeInterface])
      ),
    [runtimeInterfacesQuery.data]
  )
  const routeTrafficStatus =
    loadedConfig &&
    runtimeOutboundsQuery.data?.status === 200 &&
    runtimeInterfacesQuery.data?.status === 200
      ? "ready"
      : configQuery.isError ||
          runtimeOutboundsQuery.isError ||
          runtimeInterfacesQuery.isError
        ? "error"
        : "loading"
  const diagnosticsDownloadReady =
    Boolean(loadedConfig) &&
    Boolean(serviceHealth) &&
    Boolean(routingHealth) &&
    runtimeOutboundsQuery.data?.status === 200 &&
    dnsCheckStatus !== "idle" &&
    dnsCheckStatus !== "checking" &&
    !configIsDraft

  const routingHealthErrorMessage = routingHealthQuery.isError
    ? getRoutingHealthErrorMessage(routingHealthQuery.error, t)
    : null

  // The dashboard has no PageHeader — its heading is the status line — so the
  // browser tab is named here instead.
  useDocumentTitle(t("nav.items.systemMonitor"))

  return (
    // 24px между карточками — как в конфигураторе KeeneticOS: там каждая
    // карточка дашборда лежит в `.ndw-drag-panel__row` с `margin-bottom: 24px`,
    // а колонки разведены на 12px (`.ndw-drag-panel { gap: normal 12px }`).
    // Внутри сеток у нас так и было, а между ними стояло 12px, и одинаковые по
    // сути промежутки читались как разные.
    <div className="space-y-6">
      <SystemStatusSummary
        configIsDraft={configIsDraft}
        listCount={Object.keys(loadedConfig?.lists ?? {}).length}
        outbounds={dashboardRuntimeOutbounds}
        outboundsQueryFailed={runtimeOutboundsQuery.isError}
        routingOverall={routingHealth?.overall}
        ruleCount={loadedConfig?.route?.rules?.length ?? 0}
        service={serviceHealth}
        serviceQueryFailed={serviceHealthQuery.isError}
      >
        <RouterInfoPanel />
      </SystemStatusSummary>

      <div className="grid gap-x-3 gap-y-6 xl:grid-cols-5">
        <SectionCard
          className="h-full scroll-mt-24 xl:col-span-3"
          id={dashboardSectionIds.outbounds}
          title={t("overview.outbounds.title")}
        >
          {configQuery.isLoading ? <TableSkeleton /> : null}
          {configQuery.isError || runtimeOutboundsQuery.isError ? (
            <Alert variant="destructive">
              <AlertDescription>
                {t("overview.outbounds.loadError")}
              </AlertDescription>
            </Alert>
          ) : null}
          {!configQuery.isLoading &&
          (loadedConfig?.outbounds ?? []).length === 0 ? (
            <ListPlaceholder
              action={
                <Button onClick={() => navigate("/setup")}>
                  <WandSparklesIcon className="mr-1 h-4 w-4" />
                  {t("overview.outbounds.startSetup")}
                </Button>
              }
              description={t("overview.outbounds.emptyDescription")}
              title={t("overview.outbounds.emptyTitle")}
            />
          ) : null}
          {(loadedConfig?.outbounds ?? []).length > 0 ? (
            <>
              <OutboundStateList
                outbounds={loadedConfig?.outbounds ?? []}
                rules={loadedConfig?.route?.rules ?? []}
                runtimeByTag={runtimeOutboundByTag}
              />
              <ActiveInterfaceTraffic
                outbounds={loadedConfig?.outbounds ?? []}
                rules={loadedConfig?.route?.rules ?? []}
                runtimeByTag={runtimeOutboundByTag}
                runtimeInterfaceByName={runtimeInterfaceByName}
                transports={transportStatuses ?? []}
              />
            </>
          ) : null}
        </SectionCard>

        <div className="space-y-6 xl:col-span-2">
          <div className="scroll-mt-24" id={dashboardSectionIds.service}>
            <ServicesStatusCard />
          </div>
          {/* Под службами, в той же колонке: «куда уходит трафик» — вопрос,
              который задают после «работает ли всё». */}
          <RouteTrafficShareCard
            outbounds={loadedConfig?.outbounds ?? []}
            rules={loadedConfig?.route?.rules ?? []}
            runtimeByTag={runtimeOutboundByTag}
            runtimeInterfaceByName={runtimeInterfaceByName}
            status={routeTrafficStatus}
          />
        </div>
      </div>

      <RoutingTestPanel
        lists={loadedConfig?.lists}
        outbounds={loadedConfig?.outbounds}
      />

      <div className="grid gap-x-3 gap-y-6 xl:grid-cols-3">
        <div className="scroll-mt-24" id={dashboardSectionIds.dns}>
          <DnsCheckWidget
            dnsProbeEnabled={Boolean(loadedConfig?.dns?.dns_test_server)}
            onStatusChange={setDnsCheckStatus}
          />
        </div>

        <SectionCard
          className="h-full scroll-mt-24 xl:col-span-2"
          contentClassName="flex flex-1 flex-col"
          id={dashboardSectionIds.routing}
          title={t("overview.routing.title")}
          action={
            <Button
              size="sm"
              variant="outline"
              disabled={!diagnosticsDownloadReady}
              onClick={() => setIsDiagnosticsDialogOpen(true)}
            >
              <Download className="h-4 w-4" />
              {t("overview.diagnosticsDownload.button")}
            </Button>
          }
        >
          {routingHealthQuery.isLoading ? <TableSkeleton /> : null}
          {routingHealthQuery.isError ? (
            <Alert variant="destructive">
              <AlertDescription className="whitespace-pre-wrap">
                {routingHealthErrorMessage}
              </AlertDescription>
            </Alert>
          ) : null}
          {routingHealth &&
          routingHealth.firewall_rules.length === 0 &&
          routingHealth.route_tables.length === 0 &&
          routingHealth.policy_rules.length === 0 ? (
            <ListPlaceholder
              description={t("overview.routing.emptyDescription")}
              title={t("overview.routing.emptyTitle")}
            />
          ) : null}
          {routingHealth &&
          (routingHealth.firewall_rules.length > 0 ||
            routingHealth.route_tables.length > 0 ||
            routingHealth.policy_rules.length > 0) ? (
            <RoutingHealthCard routingHealth={routingHealth} />
          ) : null}
        </SectionCard>
      </div>

      {loadedConfig &&
      serviceHealth &&
      routingHealth &&
      runtimeOutboundsQuery.data?.status === 200 ? (
        <DiagnosticsDownloadDialog
          config={loadedConfig}
          dnsCheckStatus={dnsCheckStatus}
          onOpenChange={setIsDiagnosticsDialogOpen}
          open={isDiagnosticsDialogOpen}
          routingHealth={routingHealth}
          runtimeOutbounds={runtimeOutboundsQuery.data.data}
          serviceHealth={serviceHealth}
        />
      ) : null}
    </div>
  )
}

function getRoutingHealthErrorMessage(
  error: unknown,
  t: (key: string) => string
) {
  if (error && typeof error === "object" && "error" in error) {
    const message = (error as { error?: unknown }).error
    if (typeof message === "string" && message.trim().length > 0) {
      return message
    }
  }

  return (
    getApiErrorMessage(error as ApiError | null) ||
    t("overview.routing.loadError")
  )
}

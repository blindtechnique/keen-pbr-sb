import { useMemo, useState } from "react"
import { useTranslation } from "react-i18next"
import { Download } from "lucide-react"

import type { ApiError } from "@/api/client"

import type { DnsCheckStatus } from "@/hooks/use-dns-check"
import {
  useGetConfig,
  useGetHealthRouting,
  useGetHealthService,
  useGetRuntimeOutbounds,
} from "@/api/queries"
import { selectConfig } from "@/api/selectors"
import { Button } from "@/components/ui/button"
import { Alert, AlertDescription } from "@/components/ui/alert"
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyTitle,
} from "@/components/ui/empty"
import { Skeleton } from "@/components/ui/skeleton"
import { SectionCard } from "@/components/shared/section-card"
import { RoutingHealthCard } from "@/components/overview/routing-health-card"
import { DnsCheckWidget } from "@/components/overview/dns-check-widget"
import { OutboundStateList } from "@/components/overview/outbound-state-list"
import { ServicesStatusCard } from "@/components/overview/services-status-card"
import { RouterInfoCard } from "@/components/overview/router-info-card"
import { DiagnosticsDownloadDialog } from "@/components/overview/diagnostics-download-dialog"
import { RoutingTestPanel } from "@/components/overview/routing-test-panel"
import { getApiErrorMessage } from "@/lib/api-errors"

const SERVICE_HEALTH_REFETCH_INTERVAL_MS = 30_000

export function OverviewPage() {
  const { t } = useTranslation()
  const [dnsCheckStatus, setDnsCheckStatus] = useState<DnsCheckStatus>("idle")
  const [isDiagnosticsDialogOpen, setIsDiagnosticsDialogOpen] = useState(false)
  const serviceHealthQuery = useGetHealthService({
    query: {
      refetchInterval: SERVICE_HEALTH_REFETCH_INTERVAL_MS,
      refetchIntervalInBackground: false,
    },
  })
  const configQuery = useGetConfig()
  const routingHealthQuery = useGetHealthRouting({
    query: {
      refetchInterval: 45_000,
      refetchIntervalInBackground: false,
    },
  })
  const runtimeOutboundsQuery = useGetRuntimeOutbounds({
    query: {
      refetchInterval: 30_000,
      refetchIntervalInBackground: false,
    },
  })

  const serviceHealth =
    serviceHealthQuery.data?.status === 200
      ? serviceHealthQuery.data.data
      : undefined
  const loadedConfig = selectConfig(configQuery.data)
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
  const runtimeOutboundByTag = useMemo(
    () =>
      new Map(
        runtimeOutbounds.map((runtimeOutbound) => [
          runtimeOutbound.tag,
          runtimeOutbound,
        ])
      ),
    [runtimeOutbounds]
  )
  const configIsDraft =
    configQuery.data?.status === 200 ? configQuery.data.data.is_draft : false

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

  return (
    <div className="space-y-3">
      <div className="grid gap-3 xl:grid-cols-3">
        <RouterInfoCard />

        <DnsCheckWidget
          dnsProbeEnabled={Boolean(loadedConfig?.dns?.dns_test_server)}
          onStatusChange={setDnsCheckStatus}
        />

        <ServicesStatusCard />
      </div>

      <RoutingTestPanel />

      <div className="grid gap-3 xl:grid-cols-2">
        <SectionCard className="h-full" title={t("overview.outbounds.title")}>
          {configQuery.isLoading ? <TableSkeleton /> : null}
          {configQuery.isError || runtimeOutboundsQuery.isError ? (
            <Alert className="border-destructive/30 bg-destructive/5 text-destructive">
              <AlertDescription>
                {t("overview.outbounds.loadError")}
              </AlertDescription>
            </Alert>
          ) : null}
          {!configQuery.isLoading && (loadedConfig?.outbounds ?? []).length === 0 ? (
            <Empty className="border">
              <EmptyHeader>
                <EmptyTitle>{t("overview.outbounds.emptyTitle")}</EmptyTitle>
                <EmptyDescription>
                  {t("overview.outbounds.emptyDescription")}
                </EmptyDescription>
              </EmptyHeader>
            </Empty>
          ) : null}
          {(loadedConfig?.outbounds ?? []).length > 0 ? (
            <OutboundStateList
              outbounds={loadedConfig?.outbounds ?? []}
              rules={loadedConfig?.route?.rules ?? []}
              runtimeByTag={runtimeOutboundByTag}
            />
          ) : null}
        </SectionCard>

        <SectionCard
          className="h-full"
          contentClassName="flex flex-1 flex-col"
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
            <Alert className="border-destructive/30 bg-destructive/5 text-destructive">
              <AlertDescription className="whitespace-pre-wrap">
                {routingHealthErrorMessage}
              </AlertDescription>
            </Alert>
          ) : null}
          {routingHealth &&
          routingHealth.firewall_rules.length === 0 &&
          routingHealth.route_tables.length === 0 &&
          routingHealth.policy_rules.length === 0 ? (
            <Empty className="border">
              <EmptyHeader>
                <EmptyTitle>{t("overview.routing.emptyTitle")}</EmptyTitle>
                <EmptyDescription>
                  {t("overview.routing.emptyDescription")}
                </EmptyDescription>
              </EmptyHeader>
            </Empty>
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


function TableSkeleton() {
  return (
    <div className="space-y-2">
      <Skeleton className="h-10 w-full" />
      <Skeleton className="h-10 w-full" />
      <Skeleton className="h-10 w-full" />
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




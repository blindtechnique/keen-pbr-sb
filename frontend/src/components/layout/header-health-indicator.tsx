import { CircleAlertIcon, CircleCheckBigIcon, CircleXIcon } from "lucide-react"
import { useTranslation } from "react-i18next"

import {
  useGetConfig,
  useGetHealthService,
  useGetRuntimeOutbounds,
  useGetTransports,
} from "@/api/queries"
import { selectConfig } from "@/api/selectors"
import { useStatusEventConnectionState } from "@/api/status-event-connection"
import {
  getHeaderHealthTone,
  type HeaderHealthTone,
} from "@/components/layout/header-health-state"
import { selectDashboardRuntimeOutbounds } from "@/components/overview/dashboard-outbound-relevance"
import { cn } from "@/lib/utils"

const TONE_STYLES: Record<HeaderHealthTone, string> = {
  healthy: "text-success",
  attention: "text-warning-foreground",
  failed: "text-destructive",
}

export function HeaderHealthIndicator() {
  const { t } = useTranslation()
  const healthQuery = useGetHealthService()
  const outboundsQuery = useGetRuntimeOutbounds()
  const transportsQuery = useGetTransports()
  // Тот же запрос, что уже держат страницы, — react-query отдаёт его из кэша.
  // Без правил индикатор не отличает упавший туннель со списками от упавшего
  // туннеля, которым никто не пользуется, и краснеет на обоих.
  const configQuery = useGetConfig()
  const statusEvents = useStatusEventConnectionState()
  const service =
    healthQuery.data?.status === 200 ? healthQuery.data.data : undefined
  const rawOutbounds =
    outboundsQuery.data?.status === 200
      ? outboundsQuery.data.data.outbounds
      : undefined
  const transports =
    transportsQuery.data?.status === 200 ? transportsQuery.data.data : undefined
  const outbounds = rawOutbounds
    ? selectDashboardRuntimeOutbounds({
        runtimeOutbounds: rawOutbounds,
        transports,
      })
    : undefined
  const tone = getHeaderHealthTone({
    outbounds,
    outboundsQueryFailed: outboundsQuery.isError,
    routeRules: selectConfig(configQuery.data)?.route?.rules,
    service,
    serviceQueryFailed: healthQuery.isError,
    statusEvents,
  })
  const label = t(`headerHealth.${tone}`)
  const Icon =
    tone === "healthy"
      ? CircleCheckBigIcon
      : tone === "failed"
        ? CircleXIcon
        : CircleAlertIcon

  return (
    <span
      aria-atomic="true"
      aria-label={label}
      className={cn(
        "inline-flex size-[38px] shrink-0 items-center justify-center",
        TONE_STYLES[tone]
      )}
      role="status"
      title={label}
    >
      <Icon aria-hidden="true" className="size-5 stroke-[2.25]" />
    </span>
  )
}

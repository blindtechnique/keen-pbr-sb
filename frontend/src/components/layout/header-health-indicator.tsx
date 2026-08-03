import { CircleAlertIcon, CircleCheckBigIcon, CircleXIcon } from "lucide-react"
import { useTranslation } from "react-i18next"

import { useGetHealthService, useGetRuntimeOutbounds } from "@/api/queries"
import { useStatusEventConnectionState } from "@/api/status-event-connection"
import {
  getHeaderHealthTone,
  type HeaderHealthTone,
} from "@/components/layout/header-health-state"
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
  const statusEvents = useStatusEventConnectionState()
  const service =
    healthQuery.data?.status === 200 ? healthQuery.data.data : undefined
  const outbounds =
    outboundsQuery.data?.status === 200
      ? outboundsQuery.data.data.outbounds
      : undefined
  const tone = getHeaderHealthTone({
    outbounds,
    outboundsQueryFailed: outboundsQuery.isError,
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

import { RotateCw } from "lucide-react"
import { useTranslation } from "react-i18next"

import type { LatencyProbe } from "@/components/transports/transport-latency-model"
import { selectVisibleLatency } from "@/components/transports/transport-latency-model"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"

export function TransportLatencyPill({
  probe,
  runtimeMilliseconds,
  onRefresh,
  refreshing,
}: {
  readonly probe?: LatencyProbe
  readonly runtimeMilliseconds?: number
  readonly onRefresh?: () => void
  readonly refreshing?: boolean
}) {
  const { t } = useTranslation()
  const latency = selectVisibleLatency(probe, runtimeMilliseconds)

  if (!latency && !onRefresh) {
    return null
  }

  return (
    <span className="inline-flex min-w-0 items-center gap-1">
      <Badge
        className="shrink-0"
        size="xs"
        variant={latency ? "success" : "secondary"}
      >
        {latency
          ? t("transports.latencyValue", { value: latency.milliseconds })
          : t("transports.latencyUnavailable")}
      </Badge>
      {latency?.ageSeconds !== undefined ? (
        <span className="truncate text-xs text-muted-foreground tabular-nums">
          {t("transports.latencyAge", { seconds: latency.ageSeconds })}
        </span>
      ) : null}
      {onRefresh ? (
        <Button
          aria-label={t("transports.latencyRefresh")}
          className="size-6 shrink-0"
          disabled={refreshing}
          onClick={onRefresh}
          size="icon"
          title={t("transports.latencyRefresh")}
          variant="ghost"
        >
          <RotateCw className={cn("size-3", refreshing && "animate-spin")} />
        </Button>
      ) : null}
    </span>
  )
}

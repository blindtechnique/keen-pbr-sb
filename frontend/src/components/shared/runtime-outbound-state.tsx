import type { RuntimeOutboundState } from "@/api/generated/model"
import { Badge } from "@/components/ui/badge"

type TranslateFn = (key: string, options?: Record<string, unknown>) => string

export function RuntimeOutboundEntry({
  runtimeState,
  title,
  t,
}: {
  runtimeState?: RuntimeOutboundState
  title?: string
  t: TranslateFn
}) {
  return title ? (
    <RuntimeOutboundStatusLabel
      runtimeState={runtimeState}
      t={t}
      title={title}
    />
  ) : null
}

export function RuntimeOutboundStatusLabel({
  runtimeState,
  title,
  t,
}: {
  runtimeState?: RuntimeOutboundState
  title: string
  t: TranslateFn
}) {
  return (
    <div className="flex min-w-0 items-center gap-2">
      <span className="truncate font-medium">{title}</span>
      <Badge
        size="xs"
        variant={
          runtimeState?.status === "healthy"
            ? "success"
            : runtimeState?.status === "degraded"
              ? "warning"
              : runtimeState?.status === "unavailable"
                ? "destructive"
                : "outline"
        }
      >
        {t(`runtime.outboundStatus.${runtimeState?.status ?? "unknown"}`)}
      </Badge>
    </div>
  )
}

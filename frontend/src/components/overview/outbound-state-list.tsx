import { useTranslation } from "react-i18next"

import type {
  Outbound,
  RuntimeInterfaceState,
  RuntimeOutboundState,
} from "@/api/generated/model"
import { Badge } from "@/components/ui/badge"
import { useInterfaceProtocols } from "@/hooks/use-interface-protocols"
import { cn } from "@/lib/utils"

/**
 * Точки выхода на дашборде — по строке на каждую.
 *
 * Прежняя версия рядом с одним и тем же выходом ставила «Исправен», «UP»,
 * «Активен», значок типа и имя ядра — пять способов сказать примерно одно.
 * Здесь на строку приходится ровно четыре вещи: жив ли, как называется, чем
 * работает и насколько быстро отвечает. У групп резервирования под строкой
 * стоит порядок обхода, потому что это единственное, чего по названию не
 * узнать.
 */
export function OutboundStateList({
  outbounds,
  runtimeByTag,
}: {
  outbounds: Outbound[]
  runtimeByTag: Map<string, RuntimeOutboundState>
}) {
  const { t } = useTranslation()
  const { protocolOf, protocolOfGroup } = useInterfaceProtocols()

  const interfaceOfTag = (tag: string) =>
    outbounds.find((item) => item.tag === tag)?.interface ?? ""

  return (
    <div className="divide-y">
      {outbounds.map((outbound) => {
        const runtime = runtimeByTag.get(outbound.tag)
        const isGroup = outbound.type === "urltest"
        const members = runtime?.interfaces ?? []
        const protocol = isGroup
          ? protocolOfGroup(outbound, interfaceOfTag)
          : protocolOf(outbound.interface ?? "")
        const latency = activeLatency(members)

        return (
          <div className="py-2 first:pt-0 last:pb-0" key={outbound.tag}>
            <div className="flex min-w-0 items-center gap-2">
              <HealthDot status={runtime?.status} />
              <span className="truncate text-sm font-medium">
                {outbound.tag}
              </span>
              {protocol ? (
                <Badge
                  className="shrink-0 font-mono text-[10px]"
                  size="xs"
                  variant="outline"
                >
                  {protocol}
                </Badge>
              ) : null}
              <span className="ml-auto shrink-0 text-xs tabular-nums text-muted-foreground">
                {latency !== undefined
                  ? t("transports.latencyValue", { value: latency })
                  : t(`overview.outbounds.status.${runtime?.status ?? "unknown"}`, {
                      defaultValue: "",
                    })}
              </span>
            </div>

            {/* Порядок обхода показывается только у групп: у одиночного выхода
                он состоял бы из него самого. */}
            {isGroup && members.length > 0 ? (
              <div className="mt-1 flex flex-wrap items-center gap-1 pl-4 text-xs">
                {members.map((member, index) => (
                  <span
                    className="flex items-center gap-1"
                    key={member.outbound_tag}
                  >
                    {index > 0 ? (
                      <span className="text-muted-foreground">→</span>
                    ) : null}
                    <span
                      className={cn(
                        "rounded px-1.5 py-0.5",
                        member.status === "active"
                          ? "bg-success/10 text-success"
                          : "text-muted-foreground"
                      )}
                    >
                      {member.outbound_tag}
                    </span>
                  </span>
                ))}
              </div>
            ) : null}
          </div>
        )
      })}
    </div>
  )
}

function HealthDot({ status }: { status?: string }) {
  return (
    <span
      className={cn(
        "size-2 shrink-0 rounded-full",
        status === "healthy"
          ? "bg-success"
          : status === "degraded" || status === "unavailable"
            ? "bg-destructive"
            : "bg-muted-foreground/50"
      )}
    />
  )
}

/** Задержка того участника, через который трафик идёт прямо сейчас. */
function activeLatency(members: RuntimeInterfaceState[]): number | undefined {
  const active = members.find((member) => member.status === "active")
  const source = active ?? members[0]
  return typeof source?.latency_ms === "number" ? source.latency_ms : undefined
}

import { useTranslation } from "react-i18next"

import type {
  Outbound,
  RouteRule,
  RuntimeInterfaceState,
  RuntimeOutboundState,
} from "@/api/generated/model"
import { Badge } from "@/components/ui/badge"
import { useInterfaceProtocols } from "@/hooks/use-interface-protocols"
import { cn } from "@/lib/utils"

/**
 * Точки выхода на дашборде.
 *
 * Дашборд отвечает на один вопрос: куда сейчас идёт трафик и всё ли цело.
 * Ровный список, где `wan`, `block` и шесть незадействованных туннелей
 * выглядят так же важно, как группа, через которую ходят семь списков, на
 * этот вопрос не отвечает. Поэтому сверху сводка, дальше те, кто реально
 * везёт трафик, а незадействованные свёрнуты в одну строку — но только пока
 * с ними всё в порядке: сломанное поднимается наверх.
 */
export function OutboundStateList({
  outbounds,
  runtimeByTag,
  rules = [],
}: {
  outbounds: Outbound[]
  runtimeByTag: Map<string, RuntimeOutboundState>
  rules?: RouteRule[]
}) {
  const { t } = useTranslation()
  const { protocolOf, protocolOfGroup } = useInterfaceProtocols()

  const interfaceOfTag = (tag: string) =>
    outbounds.find((item) => item.tag === tag)?.interface ?? ""

  const listsByTag = new Map<string, number>()
  for (const rule of rules) {
    if (!rule.outbound) continue
    listsByTag.set(
      rule.outbound,
      (listsByTag.get(rule.outbound) ?? 0) + (rule.list?.length ?? 0)
    )
  }

  const entries = outbounds.map((outbound) => {
    const runtime = runtimeByTag.get(outbound.tag)
    return {
      outbound,
      runtime,
      lists: listsByTag.get(outbound.tag) ?? 0,
      broken:
        runtime?.status === "degraded" || runtime?.status === "unavailable",
    }
  })

  // Сводка отвечает на главный вопрос раньше, чем глаз дойдёт до списка.
  const totals = { tunnels: 0, direct: 0, blocked: 0 }
  for (const entry of entries) {
    if (entry.lists === 0) continue
    if (entry.outbound.type === "blackhole") totals.blocked += entry.lists
    else if (entry.outbound.type === "table") totals.direct += entry.lists
    else totals.tunnels += entry.lists
  }

  const important = entries
    .filter((entry) => entry.lists > 0 || entry.broken)
    .sort((a, b) => Number(b.broken) - Number(a.broken) || b.lists - a.lists)
  const idle = entries.filter((entry) => entry.lists === 0 && !entry.broken)

  return (
    <div className="space-y-1">
      <div className="flex flex-wrap gap-1.5 border-b pb-2.5 text-xs">
        <Badge size="xs" variant={totals.tunnels > 0 ? "default" : "secondary"}>
          {t("overview.outbounds.summary.tunnels", { count: totals.tunnels })}
        </Badge>
        <Badge size="xs" variant="secondary">
          {t("overview.outbounds.summary.direct", { count: totals.direct })}
        </Badge>
        <Badge size="xs" variant="secondary">
          {t("overview.outbounds.summary.blocked", { count: totals.blocked })}
        </Badge>
      </div>

      {important.map(({ outbound, runtime, lists }) => {
        const isGroup = outbound.type === "urltest"
        const members = runtime?.interfaces ?? []
        const protocol = isGroup
          ? protocolOfGroup(outbound, interfaceOfTag)
          : protocolOf(outbound.interface ?? "")

        return (
          <div className="pt-1.5" key={outbound.tag}>
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
              {lists > 0 ? (
                <span className="shrink-0 text-xs text-muted-foreground">
                  {t("overview.outbounds.listCount", { count: lists })}
                </span>
              ) : null}
              <span className="ml-auto shrink-0 text-xs tabular-nums text-muted-foreground">
                {activeLatency(members) !== undefined
                  ? t("transports.latencyValue", {
                      value: activeLatency(members),
                    })
                  : t(
                      `overview.outbounds.status.${runtime?.status ?? "unknown"}`,
                      { defaultValue: "" }
                    )}
              </span>
            </div>
            <p className="pl-4 text-xs text-muted-foreground">
              {describeEntry(outbound, members, t)}
            </p>
          </div>
        )
      })}

      {idle.length > 0 ? (
        <p className="border-t pt-2 text-xs text-muted-foreground">
          {t("overview.outbounds.idle", {
            count: idle.length,
            names: idle.map((entry) => entry.outbound.tag).join(", "),
          })}
        </p>
      ) : null}
    </div>
  )
}

/**
 * Строка под названием: у групп — кто везёт сейчас и кто подхватит, у
 * системных выходов — что они вообще делают. «wan» и «block» ничего не
 * говорят человеку, который их не заводил.
 */
function describeEntry(
  outbound: Outbound,
  members: RuntimeInterfaceState[],
  t: (key: string, options?: Record<string, unknown>) => string
): string {
  if (outbound.type === "table") {
    return t("overview.outbounds.hint.table")
  }
  if (outbound.type === "blackhole") {
    return t("overview.outbounds.hint.blackhole")
  }
  if (outbound.type === "ignore") {
    return t("overview.outbounds.hint.ignore")
  }
  if (outbound.type !== "urltest") {
    return ""
  }

  const active = members.find((member) => member.status === "active")
  const backup = members.find((member) => member.outbound_tag !== active?.outbound_tag)
  if (!active) {
    return t("overview.outbounds.hint.groupIdle")
  }
  return backup
    ? t("overview.outbounds.hint.groupVia", {
        active: active.outbound_tag,
        backup: backup.outbound_tag,
      })
    : t("overview.outbounds.hint.groupViaOnly", {
        active: active.outbound_tag,
      })
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

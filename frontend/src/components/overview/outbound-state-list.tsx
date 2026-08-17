import { useState } from "react"
import { useTranslation } from "react-i18next"
import { ChevronDownIcon, CircleAlert } from "lucide-react"
import { Link } from "wouter"

import type {
  Outbound,
  RouteRule,
  RuntimeInterfaceState,
  RuntimeOutboundState,
} from "@/api/generated/model"
import {
  activeOutboundMember,
  outboundManagementHref,
  outboundRuntimeIssues,
  outboundTrafficBucket,
} from "@/components/overview/outbound-state-model"
import { countEnabledRouteRuleListsByOutbound } from "@/components/overview/dashboard-outbound-relevance"
import { Badge } from "@/components/ui/badge"
import { useInterfaceProtocols } from "@/hooks/use-interface-protocols"
import {
  createOutboundDisplayNameMap,
  getOutboundDisplayName,
  getOutboundReferenceLabel,
} from "@/lib/outbound-display"
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
  const outboundDisplayNames = createOutboundDisplayNameMap(outbounds)

  const interfaceOfTag = (tag: string) =>
    outbounds.find((item) => item.tag === tag)?.interface ?? ""

  const listsByTag = countEnabledRouteRuleListsByOutbound(rules)

  const entries = outbounds.map((outbound) => {
    const runtime = runtimeByTag.get(outbound.tag)
    const configuredProtocol =
      outbound.type === "urltest"
        ? protocolOfGroup(outbound, interfaceOfTag)
        : protocolOf(outbound.interface ?? "")
    const runtimeProtocols = (runtime?.interfaces ?? [])
      .map((member) => protocolOf(member.interface_name))
      .filter(Boolean)
    const protocol = [
      ...new Set(
        configuredProtocol
          ? [configuredProtocol, ...runtimeProtocols]
          : runtimeProtocols
      ),
    ].join("+")
    return {
      outbound,
      runtime,
      protocol,
      lists: listsByTag.get(outbound.tag) ?? 0,
      broken:
        runtime?.status === "degraded" || runtime?.status === "unavailable",
    }
  })

  // Сводка отвечает на главный вопрос раньше, чем глаз дойдёт до списка.
  const totals = { tunnels: 0, direct: 0, blocked: 0 }
  for (const entry of entries) {
    if (entry.lists === 0) continue
    const bucket = outboundTrafficBucket(entry.outbound, entry.protocol)
    totals[bucket] += entry.lists
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

      {important.map(({ outbound, runtime, lists, protocol }) => {
        const members = runtime?.interfaces ?? []
        const activeMember = activeOutboundMember(runtime)
        const activeMemberName = activeMember
          ? (outboundDisplayNames.get(activeMember.outbound_tag) ??
            activeMember.outbound_tag)
          : undefined
        const issues = outboundRuntimeIssues(runtime)
        const hint = describeEntry(
          outbound,
          members,
          outboundDisplayNames,
          protocol,
          t
        )

        return (
          <div className="pt-1.5" key={outbound.tag}>
            {/* The name owns the first line on a phone. In one row the badges
                and the latency are all shrink-0, so the name was the only
                flexible child and collapsed to a single letter: "AWG bound"
                rendered as "A". Desktop keeps the original single row. */}
            <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
              <div className="flex w-full min-w-0 items-center gap-2 sm:w-auto sm:flex-1">
                <HealthDot status={runtime?.status} />
                <span
                  className="min-w-0 truncate text-sm font-medium"
                  title={getOutboundReferenceLabel(outbound)}
                >
                  {getOutboundDisplayName(outbound)}
                </span>
              </div>
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
              {outbound.type === "urltest" && activeMemberName ? (
                <Badge
                  // A phone gives this its own line, so capping it at 12rem
                  // there turned "Активен: sddvpn mooo AWG" into "dvpn".
                  className="max-w-full shrink truncate sm:max-w-48"
                  size="xs"
                  title={activeMemberName}
                  variant="success"
                >
                  {t("overview.outbounds.activeMember", {
                    name: activeMemberName,
                  })}
                </Badge>
              ) : null}
              <span className="ml-auto shrink-0 text-xs text-muted-foreground tabular-nums">
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
            {hint ? (
              <p className="pl-4 text-xs text-muted-foreground">{hint}</p>
            ) : null}
            {issues.length > 0 ? (
              <div className="space-y-0.5 pt-0.5 pl-4 text-xs">
                {issues.map((issue) => {
                  const reason = t(`overview.outbounds.issue.${issue.code}`)
                  const memberName = issue.memberTag
                    ? (outboundDisplayNames.get(issue.memberTag) ??
                      issue.memberTag)
                    : undefined
                  return (
                    <p
                      className={cn(
                        "flex items-start gap-1.5",
                        issue.tone === "error"
                          ? "text-destructive"
                          : "text-warning-foreground"
                      )}
                      key={`${issue.memberTag ?? "group"}:${issue.code}`}
                    >
                      <CircleAlert
                        aria-hidden="true"
                        className="mt-0.5 size-3 shrink-0"
                      />
                      <span className="min-w-0 break-words">
                        {memberName
                          ? t("overview.outbounds.issue.member", {
                              name: memberName,
                              reason,
                            })
                          : reason}
                      </span>
                    </p>
                  )
                })}
                <Link
                  className="inline-flex rounded font-medium text-primary hover:underline focus-visible:ring-2 focus-visible:ring-ring"
                  href={outboundManagementHref(outbound)}
                >
                  {t("overview.outbounds.issue.open")}
                </Link>
              </div>
            ) : null}
          </div>
        )
      })}

      {idle.length > 0 ? (
        <IdleOutbounds
          names={idle.map((entry) => getOutboundDisplayName(entry.outbound))}
        />
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
  outboundDisplayNames: ReadonlyMap<string, string>,
  protocol: string,
  t: (key: string, options?: Record<string, unknown>) => string
): string {
  if (outbound.type === "table") {
    return protocol
      ? t("overview.outbounds.hint.tableTunnel", { protocol })
      : t("overview.outbounds.hint.table")
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
  const backup = members.find(
    (member) => member.outbound_tag !== active?.outbound_tag
  )
  if (!active) {
    return t("overview.outbounds.hint.groupIdle")
  }
  return backup
    ? t("overview.outbounds.hint.groupBackup", {
        backup:
          outboundDisplayNames.get(backup.outbound_tag) ?? backup.outbound_tag,
      })
    : ""
}

function HealthDot({ status }: { status?: string }) {
  return (
    <span
      className={cn(
        "size-2 shrink-0 rounded-full",
        status === "healthy"
          ? "status-beacon-success bg-success"
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

/**
 * Свёрнутый счётчик неиспользуемых маршрутов.
 *
 * Раньше это был серый абзац из восьми имён в две строки — под блоком, где
 * важно то, что работает. Перечисление нужно раз в сто заходов, счётчик — всегда.
 */
function IdleOutbounds({ names }: { names: string[] }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)

  return (
    <div className="border-t pt-2">
      <button
        aria-expanded={open}
        className="-mx-1 inline-flex items-center gap-1 rounded px-1 py-0.5 text-xs text-muted-foreground hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
        onClick={() => setOpen((current) => !current)}
        type="button"
      >
        {t("overview.outbounds.idleSummary", { count: names.length })}
        <ChevronDownIcon
          aria-hidden="true"
          className={cn("size-3.5 transition-transform", open && "rotate-180")}
        />
      </button>
      {open ? (
        <p className="mt-1 text-xs text-muted-foreground">
          {t("overview.outbounds.idleNames", { names: names.join(", ") })}
        </p>
      ) : null}
    </div>
  )
}

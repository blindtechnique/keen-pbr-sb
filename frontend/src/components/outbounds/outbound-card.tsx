import { Pencil, RotateCw } from "lucide-react"
import { useTranslation } from "react-i18next"

import type {
  Outbound,
  RuntimeInterfaceState,
  RuntimeOutboundState,
} from "@/api/generated/model"
import { Badge } from "@/components/ui/badge"
import { Checkbox } from "@/components/ui/checkbox"
import { IconButtonWithTooltip } from "@/components/shared/icon-button-with-tooltip"
import { useInterfaceNames } from "@/hooks/use-interface-names"
import { cn } from "@/lib/utils"

export type OutboundUsage = {
  lists: number
  rules: number
}

/**
 * Одна запись раздела «Интерфейсы» — карточкой, а не строкой таблицы.
 *
 * Таблица показывала `ifname=nwg2`, `outbounds=a,b`, `table=254` и повторяла
 * «Исправен» рядом с «UP» и «Активен». Всё это верно и почти нечитаемо: по
 * такой строке не понять ни что она делает, ни нужна ли она вообще. Карточка
 * говорит одной фразой, что это, и добавляет то, чего в таблице не было
 * совсем — пользуется ли этим кто-нибудь.
 */
export function OutboundCard({
  outbound,
  runtimeState,
  usage,
  protocol,
  onRefreshLatency,
  refreshingLatency,
  selected,
  selectionDisabled,
  onToggleSelected,
  onEdit,
  selectLabel,
}: {
  outbound: Outbound
  runtimeState?: RuntimeOutboundState
  usage: OutboundUsage
  /** Короткая метка протокола: VLESS, AWG, WG. Пусто, если выяснить нечем. */
  protocol?: string
  /** Проверка задержки. Нативным туннелям прошивки она нужна ровно так же,
      как туннелям sing-box, а кнопка до сих пор жила только у последних. */
  onRefreshLatency?: () => void
  refreshingLatency?: boolean
  selected: boolean
  selectionDisabled?: boolean
  onToggleSelected: () => void
  onEdit: () => void
  selectLabel: string
}) {
  const { t } = useTranslation()
  const { labelFor } = useInterfaceNames()

  const latency = firstLatency(runtimeState)
  const tone = statusTone(runtimeState?.status)

  return (
    <div
      className={cn(
        "flex min-w-0 flex-col gap-2 rounded-xl border bg-card p-4 transition-colors",
        selected ? "border-primary" : "border-border"
      )}
    >
      <div className="flex min-w-0 items-start gap-3">
        <Checkbox
          aria-label={selectLabel}
          checked={selected}
          className="mt-0.5"
          disabled={selectionDisabled}
          onCheckedChange={onToggleSelected}
        />
        <div className="flex min-w-0 flex-1 flex-wrap items-center gap-x-2 gap-y-1">
          <span className="truncate text-sm font-medium text-foreground">
            {outbound.tag}
          </span>
          {protocol ? (
            <Badge className="font-mono text-[10px]" size="xs" variant="outline">
              {protocol}
            </Badge>
          ) : null}
        </div>
        <span className="flex shrink-0 items-center gap-1.5 text-xs text-muted-foreground">
          <span
            className={cn(
              "size-2 rounded-full",
              tone === "up"
                ? "bg-success"
                : tone === "down"
                  ? "bg-destructive"
                  : "bg-muted-foreground/50"
            )}
          />
          {latency !== undefined
            ? t("transports.latencyValue", { value: latency })
            : t(`overview.outbounds.status.${runtimeState?.status ?? "unknown"}`, {
                defaultValue: "",
              })}
        </span>
        {onRefreshLatency ? (
          <IconButtonWithTooltip
            className="-mt-1 size-7 shrink-0"
            disabled={refreshingLatency}
            label={t("transports.latencyRefresh")}
            onClick={onRefreshLatency}
            size="icon"
            variant="ghost"
          >
            <RotateCw
              className={cn("h-3.5 w-3.5", refreshingLatency && "animate-spin")}
            />
          </IconButtonWithTooltip>
        ) : null}
        <IconButtonWithTooltip
          className="-mt-1 size-7 shrink-0"
          label={t("common.edit")}
          onClick={onEdit}
          size="icon"
          variant="ghost"
        >
          <Pencil className="h-4 w-4" />
        </IconButtonWithTooltip>
      </div>

      <p className="text-sm text-foreground">
        {describeOutbound(outbound, labelFor, t)}
      </p>

      {outbound.type === "urltest" ? (
        <MemberChain members={runtimeState?.interfaces ?? []} t={t} />
      ) : null}

      <p className="text-xs text-muted-foreground">
        {usage.lists === 0 && usage.rules === 0
          ? t("pages.outbounds.usage.none")
          : t("pages.outbounds.usage.some", {
              lists: usage.lists,
              rules: usage.rules,
            })}
      </p>
    </div>
  )
}

/** Порядок обхода в группе резервирования, слева направо. */
function MemberChain({
  members,
  t,
}: {
  members: RuntimeInterfaceState[]
  t: (key: string, options?: Record<string, unknown>) => string
}) {
  if (members.length === 0) {
    return null
  }

  return (
    <div className="flex flex-wrap items-center gap-1.5 text-xs">
      {members.map((member, index) => (
        <span className="flex items-center gap-1.5" key={member.outbound_tag}>
          {index > 0 ? (
            <span className="text-muted-foreground">→</span>
          ) : null}
          <span
            className={cn(
              "flex items-center gap-1.5 rounded-md px-2 py-1",
              member.status === "active"
                ? "bg-success/10 text-success"
                : "bg-muted text-muted-foreground"
            )}
          >
            {member.outbound_tag}
            {typeof member.latency_ms === "number" ? (
              <span className="tabular-nums opacity-70">
                {t("transports.latencyValue", { value: member.latency_ms })}
              </span>
            ) : null}
          </span>
        </span>
      ))}
    </div>
  )
}

/** Одна фраза о том, что эта запись делает. */
function describeOutbound(
  outbound: Outbound,
  labelFor: (name?: string) => string,
  t: (key: string, options?: Record<string, unknown>) => string
): string {
  if (outbound.type === "interface") {
    return t("pages.outbounds.plain.interface", {
      name: labelFor(outbound.interface ?? ""),
    })
  }
  if (outbound.type === "urltest") {
    return t("pages.outbounds.plain.urltest")
  }
  if (outbound.type === "table") {
    return t("pages.outbounds.plain.table")
  }
  if (outbound.type === "blackhole") {
    return t("pages.outbounds.plain.blackhole")
  }
  return t("pages.outbounds.plain.ignore")
}

function firstLatency(runtimeState?: RuntimeOutboundState): number | undefined {
  const active = runtimeState?.interfaces?.find(
    (entry) => entry.status === "active"
  )
  return typeof active?.latency_ms === "number" ? active.latency_ms : undefined
}

function statusTone(status?: string): "up" | "down" | "unknown" {
  if (status === "healthy") return "up"
  if (status === "degraded" || status === "unavailable") return "down"
  return "unknown"
}

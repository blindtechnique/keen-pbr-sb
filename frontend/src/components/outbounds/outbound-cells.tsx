import { useTranslation } from "react-i18next"

import type {
  Outbound,
  RuntimeInterfaceState,
  RuntimeOutboundState,
} from "@/api/generated/model"
import { Badge } from "@/components/ui/badge"
import { useInterfaceDisplayNames } from "@/hooks/use-interface-display-names"
import {
  getOutboundDisplayName,
  getOutboundReferenceLabel,
} from "@/lib/outbound-display"
import { cn } from "@/lib/utils"
import { firstLatency } from "@/pages/outbounds-utils"

/**
 * Ячейки строки раздела «Маршруты и резервирование».
 *
 * Раньше каждая запись была карточкой. Карточка объясняла запись словами — это
 * стоило сохранить, — но росла по содержимому: у одной цепочка резервирования и
 * пять связей, у соседней ничего. В сетке ряд выравнивается по самой высокой,
 * и половина экрана уходила в пустоту. Сравнить задержки двух выходов по такой
 * сетке тоже нельзя: числа стоят в разных местах.
 *
 * Здесь то же самое разложено по колонкам таблицы: слова остались, пустота
 * исчезла, задержка встала в столбец и сортируется.
 */

/**
 * Название и метка протокола (VLESS, AWG, WG — пусто, если выяснить нечем).
 *
 * Бейдж переносится под имя, а не ужимает его: на узком экране имя обрезалось
 * первым и «VLESS bound» превращалось в «V.».
 */
export function OutboundName({
  outbound,
  protocol,
  withInterface = false,
}: {
  outbound: Outbound
  protocol?: string
  /**
   * Подписать интерфейс под именем — но только если он от имени отличается.
   * У большинства туннелей имя и есть имя интерфейса, и строчка «интерфейс
   * sddvpn mooo AWG» под заголовком «sddvpn mooo AWG» не сообщает ничего.
   */
  withInterface?: boolean
}) {
  const { t } = useTranslation()
  const { labelFor } = useInterfaceDisplayNames()
  const name = getOutboundDisplayName(outbound)
  const interfaceLabel = withInterface ? labelFor(outbound.interface ?? "") : ""
  const showInterface =
    Boolean(interfaceLabel) &&
    interfaceLabel.trim().toLocaleLowerCase() !==
      name.trim().toLocaleLowerCase()

  return (
    <div className="min-w-0">
      <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
        <span
          className="min-w-0 truncate font-medium"
          title={getOutboundReferenceLabel(outbound)}
        >
          {name}
        </span>
        {protocol ? (
          <Badge className="font-mono text-[10px]" size="xs" variant="outline">
            {protocol}
          </Badge>
        ) : null}
      </div>
      {showInterface ? (
        <span className="mt-0.5 block truncate text-xs text-muted-foreground">
          {t("pages.outbounds.interfaceSubline", { name: interfaceLabel })}
        </span>
      ) : null}
    </div>
  )
}

/**
 * Одной фразой: что эта запись делает.
 *
 * Осталась только у системных маршрутов. У туннеля эта фраза была одинаковой во
 * всех девяти строках и дословно повторяла соседнюю колонку; у группы
 * резервирования — вводным предложением перед единственно ценным, цепочкой.
 * А у системного маршрута другого описания нет, и строк там две.
 */
export function OutboundPurpose({ outbound }: { outbound: Outbound }) {
  const { t } = useTranslation()
  const { labelFor } = useInterfaceDisplayNames()

  return (
    <p className="text-sm text-foreground">
      {describeOutbound(outbound, labelFor, t)}
    </p>
  )
}

/** Порядок обхода группы резервирования — своя колонка, а не хвост фразы. */
export function OutboundMemberChain({
  runtimeState,
  outboundDisplayNames,
}: {
  runtimeState?: RuntimeOutboundState
  outboundDisplayNames?: ReadonlyMap<string, string>
}) {
  const { t } = useTranslation()
  const members = runtimeState?.interfaces ?? []

  if (members.length === 0) {
    return <span className="text-xs text-muted-foreground">—</span>
  }

  return (
    <MemberChain displayNames={outboundDisplayNames} members={members} t={t} />
  )
}

/** Точка состояния и задержка активного участника. */
export function OutboundStatus({
  runtimeState,
}: {
  runtimeState?: RuntimeOutboundState
}) {
  const { t } = useTranslation()
  const latency = firstLatency(runtimeState)
  const tone = statusTone(runtimeState?.status)

  return (
    <span className="inline-flex items-center gap-1.5 text-sm whitespace-nowrap text-muted-foreground">
      <span
        className={cn(
          "size-2 shrink-0 rounded-full",
          tone === "up"
            ? "status-beacon-success bg-success"
            : tone === "down"
              ? "bg-destructive"
              : "bg-muted-foreground/50"
        )}
      />
      <span className="tabular-nums">
        {latency !== undefined
          ? t("transports.latencyValue", { value: latency })
          : t(
              `overview.outbounds.status.${runtimeState?.status ?? "unknown"}`,
              {
                defaultValue: "",
              }
            )}
      </span>
    </span>
  )
}

/** Порядок обхода в группе резервирования, слева направо. */
function MemberChain({
  displayNames,
  members,
  t,
}: {
  displayNames?: ReadonlyMap<string, string>
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
          {index > 0 ? <span className="text-muted-foreground">→</span> : null}
          <span
            className={cn(
              "flex items-center gap-1.5 rounded-md px-2 py-1",
              member.status === "active"
                ? "bg-success/10 text-success"
                : "bg-muted text-muted-foreground"
            )}
          >
            <span title={member.outbound_tag}>
              {displayNames?.get(member.outbound_tag) ?? member.outbound_tag}
            </span>
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

function statusTone(status?: string): "up" | "down" | "unknown" {
  if (status === "healthy") return "up"
  if (status === "degraded" || status === "unavailable") return "down"
  return "unknown"
}

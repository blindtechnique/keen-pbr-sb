import { useMemo } from "react"
import { useTranslation } from "react-i18next"

import { KeeneticStatus } from "@/components/shared/keenetic-status"
import { Badge } from "@/components/ui/badge"
import type { NfqwsRotatorPoolState, NfqwsRotatorState } from "@/api/nfqws"
import {
  nfqwsProtocolLabel,
  parseNfqwsStrategy,
  type NfqwsPool,
} from "@/pages/nfqws-strategy-model"

/**
 * Read-only explanation of the exact strategy text shown in the raw editor.
 *
 * Разбор живёт плоскими строками с разделителями, а не сеткой карточек.
 * Карточками наверху страницы выбирают профиль — это выбор из трёх. Пул
 * выбирать не из чего: это перечисление, и рамка вокруг каждого пункта
 * давала карточку внутри карточки, а живое состояние ротатора — ещё одну
 * карточку внутри неё.
 */
export function StrategyBreakdown({
  content,
  rotatorState,
}: {
  content: string
  rotatorState?: NfqwsRotatorState
}) {
  const { t } = useTranslation()
  const summary = useMemo(() => parseNfqwsStrategy(content), [content])
  // Состояние ротатора целиком (не получено, несвежее, сервис прогревается,
  // ответ обрезан) относится ко всей стратегии, а не к отдельному пулу.
  // Строкой в каждом пуле одна и та же фраза повторялась бы восемь раз и
  // читалась как список ошибок — поэтому она стоит один раз в шапке разбора.
  const rotatorNote = rotatorState
    ? describeRotatorState(rotatorState, t)
    : undefined

  if (!summary.parseable) {
    return (
      <p className="text-sm text-muted-foreground" role="status">
        {t("nfqws.breakdown.unparseable")}
      </p>
    )
  }

  return (
    <div className="space-y-3">
      {summary.status === "partial" ? (
        <p
          className="rounded-lg border border-warning/40 bg-warning/5 px-3 py-2 text-sm text-warning-foreground"
          role="status"
        >
          {t("nfqws.breakdown.partial")}
        </p>
      ) : null}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
        <span>
          {t("nfqws.breakdown.poolCount", { count: summary.pools.length })}
        </span>
        {summary.blobCount > 0 ? (
          <span>
            {t("nfqws.breakdown.blobCount", { count: summary.blobCount })}
          </span>
        ) : null}
        {rotatorNote ? <span>{rotatorNote}</span> : null}
      </div>
      <ul className="divide-y border-y">
        {summary.pools.map((pool) => (
          <PoolRow key={pool.id} pool={pool} rotatorState={rotatorState} />
        ))}
      </ul>
    </div>
  )
}

function PoolRow({
  pool,
  rotatorState,
}: {
  pool: NfqwsPool
  rotatorState?: NfqwsRotatorState
}) {
  const { t } = useTranslation()
  const title = poolTitle(pool, t)
  const transportLabel =
    pool.transport === "tcp"
      ? "TCP"
      : pool.transport === "udp"
        ? "UDP"
        : t("nfqws.breakdown.unknownTransport")
  const live =
    pool.rotation?.stateKey && rotatorState
      ? describeLiveRotation({
          pool: rotatorState.pools[pool.rotation.stateKey],
          state: rotatorState,
          t,
        })
      : undefined

  return (
    <li className="min-w-0 space-y-1.5 py-3">
      <div className="flex min-w-0 flex-wrap items-center gap-2">
        <span className="min-w-0 truncate text-sm font-medium" title={title}>
          {title}
        </span>
        <Badge size="xs" variant={pool.filterOnly ? "success" : "secondary"}>
          {pool.filterOnly ? t("nfqws.breakdown.passthrough") : transportLabel}
        </Badge>
        {pool.protocols.map((protocol) => (
          <Badge key={protocol} size="xs" variant="outline">
            {nfqwsProtocolLabel(protocol)}
          </Badge>
        ))}
        {/* Активный слот — плашкой справа: это единственное здесь, что
            меняется само по себе, и в списке из семи пулов взгляд ищет
            именно его. */}
        {live?.slot ? (
          <KeeneticStatus className="ml-auto" tone="success">
            {live.slot}
          </KeeneticStatus>
        ) : null}
      </div>

      {pool.tcpPorts ? (
        <p className="text-xs text-muted-foreground">
          {t("nfqws.breakdown.tcpPorts", { ports: pool.tcpPorts })}
        </p>
      ) : null}
      {pool.udpPorts ? (
        <p className="text-xs text-muted-foreground">
          {t("nfqws.breakdown.udpPorts", { ports: pool.udpPorts })}
        </p>
      ) : null}

      {pool.domains.length > 0 ? (
        <p
          className="truncate text-xs text-muted-foreground"
          title={pool.domains.join(", ")}
        >
          {t("nfqws.breakdown.domains")}: {pool.domains.slice(0, 3).join(", ")}
          {pool.domains.length > 3
            ? ` ${t("nfqws.breakdown.domainsMore", {
                count: pool.domains.length - 3,
              })}`
            : ""}
        </p>
      ) : null}

      {pool.filterOnly ? (
        <p className="text-xs text-muted-foreground">
          {t("nfqws.breakdown.passthroughDescription")}
        </p>
      ) : pool.rotation ? (
        <p className="text-xs text-muted-foreground">
          {t("nfqws.breakdown.rotation", { count: pool.rotation.slots })}
          {pool.rotation.fails !== undefined
            ? ` · ${t("nfqws.breakdown.switchAfter", {
                count: pool.rotation.fails,
              })}`
            : ""}
          {pool.rotation.inseq !== undefined
            ? ` · ${t("nfqws.breakdown.inseq", {
                value: pool.rotation.inseq,
              })}`
            : ""}
          {live?.tail ? ` · ${live.tail}` : ""}
        </p>
      ) : (
        <p className="text-xs text-muted-foreground">
          {t("nfqws.breakdown.noRotation")}
        </p>
      )}

      {/* Живое состояние — строками той же строки пула, без заголовка
          «Ротация сейчас» и без подложки: заголовок над двумя строками
          требовал рамки, а рамка внутри карточки профиля и была карточкой
          в карточке. */}
      {live?.lines.map((line) => (
        <p className="text-xs text-muted-foreground" key={line}>
          {line}
        </p>
      ))}

      {pool.techniques.length > 0 ? (
        <div className="flex flex-wrap gap-1">
          {pool.techniques.map((technique) => (
            <Badge key={technique} size="xs" variant="outline">
              {technique}
            </Badge>
          ))}
        </div>
      ) : null}
    </li>
  )
}

/**
 * Почему живых чисел нет — одной фразой на весь разбор. `undefined` значит,
 * что числа есть и объяснять нечего.
 */
function describeRotatorState(
  state: NfqwsRotatorState,
  t: (key: string) => string
): string | undefined {
  if (state.status === "unsupported") {
    return t("nfqws.breakdown.liveUnsupported")
  }
  if (state.status === "stale") return t("nfqws.breakdown.liveStale")
  if (state.status === "warming") return t("nfqws.breakdown.liveStarting")
  if (state.truncated) return t("nfqws.breakdown.livePartial")
  return undefined
}

/**
 * Живое состояние конкретного пула. Активный слот уходит в плашку — это
 * единственное, что стоит видеть издалека; остальное строками под пулом.
 *
 * `tail` — короткий хвост к строке о настроенной ротации для пула, по
 * которому ротатор ещё ничего не наблюдал. Отдельным предложением эта фраза
 * повторялась в пяти строках из восьми. Числа при этом не выдумываются: нули
 * вместо «трафика ещё не было» читались бы как поломка.
 */
function describeLiveRotation({
  pool,
  state,
  t,
}: {
  pool?: NfqwsRotatorPoolState
  state: NfqwsRotatorState
  t: (key: string, options?: Record<string, unknown>) => string
}): { slot?: string; lines: string[]; tail?: string } {
  if (describeRotatorState(state, t) !== undefined) {
    // Причина уже сказана один раз в шапке разбора.
    return { lines: [] }
  }
  if (pool === undefined) {
    return { lines: [], tail: t("nfqws.breakdown.liveWarming") }
  }

  const lines: string[] = []
  let slot: string | undefined
  if (pool.active_slot !== null && pool.slot_count !== null) {
    slot = t("nfqws.breakdown.liveSlot", {
      slot: pool.active_slot,
      count: pool.slot_count,
    })
    lines.push(
      t("nfqws.breakdown.liveTargets", { count: pool.tracked_targets })
    )
  } else {
    lines.push(
      t("nfqws.breakdown.liveDiverged", { count: pool.tracked_targets })
    )
  }

  if (pool.pending_failures !== null) {
    lines.push(
      t("nfqws.breakdown.liveFailures", { count: pool.pending_failures })
    )
  } else if (pool.max_pending_failures !== null) {
    lines.push(
      t("nfqws.breakdown.liveFailuresVary", {
        count: pool.max_pending_failures,
      })
    )
  }

  return { slot, lines }
}

function poolTitle(pool: NfqwsPool, t: (key: string) => string): string {
  if (pool.domains.length > 0) {
    const first = pool.domains[0] ?? ""
    return pool.domains.length > 1
      ? `${first} +${pool.domains.length - 1}`
      : first
  }
  if (pool.name && !pool.name.endsWith("_general")) return pool.name
  if (pool.varName === "NFQWS_ARGS") return t("nfqws.breakdown.pools.main")
  if (pool.varName === "NFQWS_ARGS_QUIC") {
    return t("nfqws.breakdown.pools.quic")
  }
  if (pool.varName === "NFQWS_ARGS_UDP") {
    return t("nfqws.breakdown.pools.udp")
  }
  return pool.name ?? pool.varName
}

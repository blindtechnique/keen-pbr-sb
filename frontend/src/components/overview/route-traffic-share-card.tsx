import { useTranslation } from "react-i18next"

import type { RuntimeInterfaceInventoryEntry } from "@/api/generated/model/runtimeInterfaceInventoryEntry"
import type { Outbound } from "@/api/generated/model/outbound"
import type { RouteRule } from "@/api/generated/model/routeRule"
import type { RuntimeOutboundState } from "@/api/generated/model/runtimeOutboundState"
import { collectActiveTrafficPaths } from "@/components/overview/active-interface-traffic-model"
import {
  collectRouteTrafficShares,
  describeDonutSegment,
  type RouteTrafficSlice,
} from "@/components/overview/route-traffic-share-model"
import { SectionCard } from "@/components/shared/section-card"
import { ListPlaceholder } from "@/components/shared/list-placeholder"
import { TableSkeleton } from "@/components/shared/table-skeleton"
import { formatTrafficBytes } from "@/components/transports/interface-traffic-model"

/**
 * Кольцо накопительных счётчиков интерфейсов, используемых маршрутами.
 *
 * Это не атрибуция трафика правилам: sysfs показывает весь RX+TX интерфейса,
 * включая пакеты вне keen-pbr, а разные интерфейсы могли подняться в разное
 * время. Поэтому карточка сравнивает только видимые накопительные счётчики и
 * не делает из долей вывод о прямом обходе VPN.
 *
 * Счётчики накопительные, с момента поднятия интерфейса. Постоянного учёта у
 * нас нет, поэтому «за сутки» показать нельзя, и подпись карточки говорит об
 * этом прямо, а не оставляет догадываться.
 */
export function RouteTrafficShareCard({
  outbounds,
  rules,
  runtimeByTag,
  runtimeInterfaceByName,
  status,
  id,
}: {
  readonly outbounds: readonly Outbound[]
  readonly rules: readonly RouteRule[]
  readonly runtimeByTag: ReadonlyMap<string, RuntimeOutboundState>
  readonly runtimeInterfaceByName: ReadonlyMap<
    string,
    RuntimeInterfaceInventoryEntry
  >
  readonly status: "loading" | "error" | "ready"
  readonly id?: string
}) {
  const { i18n, t } = useTranslation()
  const locale = i18n.resolvedLanguage ?? i18n.language
  const paths = collectActiveTrafficPaths(outbounds, rules, runtimeByTag)
  const { slices, totalBytes, idleCounters, unavailableCounters } =
    collectRouteTrafficShares(
      paths,
      runtimeInterfaceByName,
      t("overview.routeTraffic.rest")
    )

  if (status === "loading") {
    return (
      <SectionCard
        description={t("overview.routeTraffic.description")}
        id={id}
        title={t("overview.routeTraffic.title")}
      >
        <TableSkeleton />
      </SectionCard>
    )
  }

  if (status === "error") {
    return (
      <SectionCard
        description={t("overview.routeTraffic.description")}
        id={id}
        title={t("overview.routeTraffic.title")}
      >
        <ListPlaceholder
          description={t("overview.routeTraffic.loadErrorDescription")}
          title={t("overview.routeTraffic.loadErrorTitle")}
          variant="error"
        />
      </SectionCard>
    )
  }

  if (slices.length === 0) {
    return (
      <SectionCard
        description={t("overview.routeTraffic.description")}
        id={id}
        title={t("overview.routeTraffic.title")}
      >
        <p className="text-sm text-muted-foreground">
          {t(
            idleCounters > 0
              ? "overview.routeTraffic.idle"
              : "overview.routeTraffic.unavailable"
          )}
        </p>
      </SectionCard>
    )
  }

  const segments = slices.reduce<
    { slice: RouteTrafficSlice; from: number; to: number }[]
  >((acc, slice) => {
    const from = acc.length === 0 ? 0 : acc[acc.length - 1].to
    acc.push({ slice, from, to: from + slice.share })
    return acc
  }, [])

  return (
    <SectionCard
      description={t("overview.routeTraffic.description")}
      id={id}
      title={t("overview.routeTraffic.title")}
    >
      {/* Раскладка по ширине самой карточки, а не окна: на дашборде карточка
          стоит в узкой колонке, и там кольцо с легендой рядом не помещается,
          хотя окно широкое. */}
      <div className="@container">
        <div className="flex flex-col items-center gap-6 @lg:flex-row @lg:items-start">
          <svg
            aria-hidden="true"
            className="size-[170px] shrink-0"
            viewBox="0 0 250 250"
          >
            <g transform="translate(125,125)">
              {segments.map(({ slice, from, to }) => (
                <path
                  d={describeDonutSegment(from, to)}
                  fill={slice.color}
                  key={slice.key}
                  // Зазор подложкой, а не пустотой: две доли близкого цвета без
                  // него сливаются в одну сплошную дугу.
                  stroke="var(--card)"
                  strokeWidth={slices.length > 1 ? 2 : 0}
                >
                  {/* Одной строкой: React не принимает массив детей у <title>,
                      а «текст {значение}» — это как раз массив. */}
                  <title>{`${slice.label}: ${formatShare(slice.share, locale)}`}</title>
                </path>
              ))}
            </g>
          </svg>

          {/* Легенда — она же таблица значений: цвет несёт узнавание, а сами
            числа стоят текстом, а не только цветом. */}
          {/* Ширина легенды ограничена: на широкой карточке строка «название …
              значение» иначе растягивается на пол-экрана, и глаз теряет, какому
              маршруту принадлежит число. */}
          <div className="w-full min-w-0 @lg:max-w-md @lg:flex-1">
            <dl className="grid grid-cols-[auto_minmax(0,1fr)_auto] items-baseline gap-x-3 gap-y-2 text-sm">
              {slices.map((slice) => (
                <LegendRow key={slice.key} locale={locale} slice={slice} />
              ))}
            </dl>
            {/* Итог отдельным списком, а не строкой той же сетки: иначе линия над
              ним разрывается промежутком между колонками. */}
            <dl className="mt-2 flex items-baseline justify-between gap-3 border-t pt-2 text-sm">
              <dt className="font-bold">{t("overview.routeTraffic.total")}</dt>
              <dd className="text-right font-medium tabular-nums">
                {formatTrafficBytes(totalBytes, locale)}
              </dd>
            </dl>
          </div>
        </div>
      </div>

      {idleCounters > 0 ? (
        <p className="mt-4 text-xs text-muted-foreground">
          {t("overview.routeTraffic.idleCounters", {
            count: idleCounters,
          })}
        </p>
      ) : null}
      {unavailableCounters > 0 ? (
        <p className="mt-2 text-xs text-muted-foreground">
          {t("overview.routeTraffic.unavailableCounters", {
            count: unavailableCounters,
          })}
        </p>
      ) : null}
    </SectionCard>
  )
}

function LegendRow({
  slice,
  locale,
}: {
  readonly slice: RouteTrafficSlice
  readonly locale: string
}) {
  return (
    <>
      <dt className="flex items-center">
        <span
          aria-hidden="true"
          className="size-3 shrink-0 rounded-[2px]"
          style={{ backgroundColor: slice.color }}
        />
      </dt>
      <dd className="min-w-0 truncate text-foreground" title={slice.label}>
        {slice.label}
      </dd>
      <dd className="text-right whitespace-nowrap tabular-nums">
        <span className="text-foreground">
          {formatTrafficBytes(slice.bytes, locale)}
        </span>
        <span className="ml-2 text-muted-foreground">
          {formatShare(slice.share, locale)}
        </span>
      </dd>
    </>
  )
}

function formatShare(share: number, locale: string) {
  return new Intl.NumberFormat(locale, {
    style: "percent",
    maximumFractionDigits: share < 0.1 ? 1 : 0,
  }).format(share)
}

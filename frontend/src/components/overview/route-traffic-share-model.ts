import type { RuntimeInterfaceInventoryEntry } from "@/api/generated/model/runtimeInterfaceInventoryEntry"

import type { ActiveTrafficPath } from "@/components/overview/active-interface-traffic-model"

/**
 * Сколько цветов раздаём маршрутам, прежде чем свернуть хвост в «Остальные».
 *
 * Кольцо читается «на глаз», а не по числам: за шестью долями глаз перестаёт их
 * различать, и седьмая уже не сообщает ничего, кроме шума. Палитра ровно на
 * шесть и проверена на различимость при дальтонизме.
 */
export const ROUTE_TRAFFIC_SHARE_LIMIT = 6

/**
 * Категориальная палитра кольца.
 *
 * Проверена валидатором в обеих темах: полоса светлоты, минимальная
 * насыщенность, различимость соседних пар при дейтеранопии и тританопии,
 * контраст к подложке. Одна и та же в светлой и тёмной теме — отдельные шаги
 * под тёмную не понадобились.
 *
 * Порядок закреплён: цвет принадлежит месту в списке, а не маршруту. Список
 * отсортирован по объёму, так что самый крупный маршрут всегда синий — это
 * привычнее, чем перекрашивание всего кольца при смене лидера.
 */
export const ROUTE_TRAFFIC_COLORS = [
  "#0086cb",
  "#e8590c",
  "#7950f2",
  "#0ca678",
  "#ae3ec9",
  "#c2255c",
] as const

/** Серый для свёрнутого хвоста: это не ещё одна категория, а «всё прочее». */
export const ROUTE_TRAFFIC_REST_COLOR = "#868e96"

export type RouteTrafficSlice = Readonly<{
  /** Ключ для React и для связи доли с легендой. */
  key: string
  label: string
  bytes: number
  /** Доля от суммы, 0…1. */
  share: number
  color: string
  /** Свёрнутый хвост из нескольких маршрутов. */
  rest: boolean
}>

export type RouteTrafficShares = Readonly<{
  slices: readonly RouteTrafficSlice[]
  totalBytes: number
  /** Поднятые маршруты с корректными, но пока нулевыми счётчиками. */
  idleCounters: number
  /** Маршруты без пригодных счётчиков или с неподнятым интерфейсом. */
  unavailableCounters: number
}>

/**
 * Доли накопительных счётчиков интерфейсов, используемых маршрутами.
 *
 * Считаем принятое плюс отправленное по физическому интерфейсу, на который
 * приземляется маршрут. Это весь трафик интерфейса, не только совпавший с
 * правилами keen-pbr; счётчики разных интерфейсов также могли начаться в
 * разное время. Из этих долей нельзя доказывать выбор конкретного правила или
 * утечку мимо VPN — подпись карточки обязана говорить об этом прямо.
 *
 * Маршруты без счётчиков в кольцо не попадают — доля в ноль процентов рисует
 * невидимую дугу и занимает цвет. Их количество возвращается отдельно, чтобы
 * карточка могла сказать, что часть маршрутов ещё не поднялась.
 */
export function collectRouteTrafficShares(
  paths: readonly ActiveTrafficPath[],
  runtimeInterfaceByName: ReadonlyMap<string, RuntimeInterfaceInventoryEntry>,
  restLabel: string
): RouteTrafficShares {
  const measured: { key: string; label: string; bytes: number }[] = []
  let idleCounters = 0
  let unavailableCounters = 0

  for (const path of paths) {
    const runtimeInterface = runtimeInterfaceByName.get(path.interfaceName)
    const traffic = runtimeInterface?.traffic
    const bytes = (traffic?.rx_bytes ?? 0) + (traffic?.tx_bytes ?? 0)
    if (
      runtimeInterface?.status !== "up" ||
      !traffic ||
      !Number.isFinite(bytes) ||
      bytes < 0
    ) {
      unavailableCounters += 1
      continue
    }
    if (bytes === 0) {
      idleCounters += 1
      continue
    }
    measured.push({ key: path.interfaceName, label: path.label, bytes })
  }

  const totalBytes = measured.reduce((sum, item) => sum + item.bytes, 0)
  if (totalBytes <= 0) {
    return {
      slices: [],
      totalBytes: 0,
      idleCounters,
      unavailableCounters,
    }
  }

  // Порядок равных объёмов сохраняем по имени: иначе два простаивающих
  // маршрута менялись бы местами при каждом опросе.
  const sorted = [...measured].sort(
    (left, right) =>
      right.bytes - left.bytes || left.key.localeCompare(right.key)
  )
  const head = sorted.slice(0, ROUTE_TRAFFIC_SHARE_LIMIT)
  const tail = sorted.slice(ROUTE_TRAFFIC_SHARE_LIMIT)

  const slices: RouteTrafficSlice[] = head.map((item, index) => ({
    key: item.key,
    label: item.label,
    bytes: item.bytes,
    share: item.bytes / totalBytes,
    color: ROUTE_TRAFFIC_COLORS[index],
    rest: false,
  }))

  if (tail.length > 0) {
    const restBytes = tail.reduce((sum, item) => sum + item.bytes, 0)
    slices.push({
      key: "__rest__",
      label: restLabel,
      bytes: restBytes,
      share: restBytes / totalBytes,
      color: ROUTE_TRAFFIC_REST_COLOR,
      rest: true,
    })
  }

  return { slices, totalBytes, idleCounters, unavailableCounters }
}

/**
 * Дуга сегмента кольца.
 *
 * Геометрия снята с монитора трафика KeeneticOS: поле 250×250, внешний радиус
 * 115, внутренний 47. Между соседними долями оставлен зазор в 2px подложкой —
 * без него две доли близкого цвета сливаются в одну.
 *
 * Единственная доля рисуется полным кольцом: дуга в 360° вырождается в точку,
 * потому что начало и конец совпадают.
 */
export function describeDonutSegment(
  startShare: number,
  endShare: number,
  outerRadius = 115,
  innerRadius = 47
): string {
  const full = endShare - startShare >= 1
  const start = shareToPoint(startShare)
  const end = shareToPoint(full ? endShare - 0.0001 : endShare)
  const large = endShare - startShare > 0.5 ? 1 : 0

  return [
    `M${point(start, outerRadius)}`,
    `A${outerRadius},${outerRadius},0,${large},1,${point(end, outerRadius)}`,
    `L${point(end, innerRadius)}`,
    `A${innerRadius},${innerRadius},0,${large},0,${point(start, innerRadius)}`,
    "Z",
  ].join("")
}

function shareToPoint(share: number) {
  // Начинаем с двенадцати часов и идём по часовой стрелке, как в прошивке.
  const angle = share * Math.PI * 2 - Math.PI / 2
  return { cos: Math.cos(angle), sin: Math.sin(angle) }
}

function point(at: { cos: number; sin: number }, radius: number) {
  return `${round(at.cos * radius)},${round(at.sin * radius)}`
}

function round(value: number) {
  return Math.abs(value) < 0.0005 ? 0 : Number(value.toFixed(3))
}

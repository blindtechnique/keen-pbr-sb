import { describe, expect, test } from "bun:test"

import type { RuntimeInterfaceInventoryEntry } from "../src/api/generated/model/runtimeInterfaceInventoryEntry"
import {
  ROUTE_TRAFFIC_COLORS,
  collectRouteTrafficShares,
  describeDonutSegment,
} from "../src/components/overview/route-traffic-share-model"

const path = (interfaceName: string, label = interfaceName) =>
  ({ interfaceName, label, status: "up" }) as never

const iface = (name: string, rx: number, tx: number) =>
  [
    name,
    {
      name,
      status: "up",
      traffic: { rx_bytes: rx, tx_bytes: tx, history: [] },
    },
  ] as unknown as [string, RuntimeInterfaceInventoryEntry]

describe("route traffic shares", () => {
  test("a share is received plus sent, over the sum of all routes", () => {
    const { slices, totalBytes } = collectRouteTrafficShares(
      [path("nwg0", "Amsterdam"), path("hy1", "Frankfurt")],
      new Map([iface("nwg0", 60, 40), iface("hy1", 200, 100)]),
      "Others"
    )
    expect(totalBytes).toBe(400)
    expect(slices.map((s) => [s.label, s.share])).toEqual([
      ["Frankfurt", 0.75],
      ["Amsterdam", 0.25],
    ])
  })

  test("colour belongs to the position, so the biggest route is always the first hue", () => {
    const { slices } = collectRouteTrafficShares(
      [path("a"), path("b")],
      new Map([iface("a", 1, 0), iface("b", 9, 0)]),
      "Others"
    )
    expect(slices[0].key).toBe("b")
    expect(slices[0].color).toBe(ROUTE_TRAFFIC_COLORS[0])
    expect(slices[1].color).toBe(ROUTE_TRAFFIC_COLORS[1])
  })

  // Больше шести долей глаз не различает, поэтому хвост сворачивается — но его
  // байты обязаны остаться в сумме, иначе проценты перестанут сходиться.
  test("beyond six routes the tail folds into one slice and keeps its bytes", () => {
    const names = ["a", "b", "c", "d", "e", "f", "g", "h"]
    const { slices, totalBytes } = collectRouteTrafficShares(
      names.map((n) => path(n)),
      new Map(names.map((n, i) => iface(n, (names.length - i) * 10, 0))),
      "Others"
    )
    expect(slices).toHaveLength(7)
    expect(slices[6].rest).toBe(true)
    expect(slices[6].label).toBe("Others")
    expect(slices[6].bytes).toBe(30) // g=20 + h=10
    expect(slices.reduce((sum, s) => sum + s.bytes, 0)).toBe(totalBytes)
    expect(slices.reduce((sum, s) => sum + s.share, 0)).toBeCloseTo(1, 10)
  })

  // Доля в ноль процентов рисует невидимую дугу и занимает цвет; такие
  // маршруты считаются отдельно, чтобы карточка могла о них сказать.
  test("down and missing interfaces are unavailable, while an up zero counter is idle", () => {
    const down = iface("down", 0, 0)
    down[1].status = "down"
    const { slices, idleCounters, unavailableCounters } =
      collectRouteTrafficShares(
        [path("up"), path("down"), path("missing")],
        new Map([iface("up", 5, 5), down]),
        "Others"
      )
    expect(slices.map((s) => s.key)).toEqual(["up"])
    expect(idleCounters).toBe(0)
    expect(unavailableCounters).toBe(2)
  })

  test("an up interface with zero bytes is idle, not unavailable", () => {
    const result = collectRouteTrafficShares(
      [path("idle")],
      new Map([iface("idle", 0, 0)]),
      "Others"
    )
    expect(result.slices).toEqual([])
    expect(result.idleCounters).toBe(1)
    expect(result.unavailableCounters).toBe(0)
  })

  test("no counters at all is an empty ring, not a division by zero", () => {
    const result = collectRouteTrafficShares([path("a")], new Map(), "Others")
    expect(result.slices).toEqual([])
    expect(result.totalBytes).toBe(0)
    expect(result.idleCounters).toBe(0)
    expect(result.unavailableCounters).toBe(1)
    expect(Number.isNaN(result.totalBytes)).toBe(false)
  })
})

describe("donut geometry", () => {
  test("a segment is an outer arc, a step inward and an inner arc back", () => {
    const d = describeDonutSegment(0, 0.25)
    expect(d).toMatch(/^M0,-115A115,115,0,0,1,115,0L47,0A47,47,0,0,0,0,-47Z$/)
  })

  test("halves and larger get the large-arc flag", () => {
    expect(describeDonutSegment(0, 0.75)).toContain("A115,115,0,1,1,")
    expect(describeDonutSegment(0, 0.25)).toContain("A115,115,0,0,1,")
  })

  // Дуга в 360° вырождается в точку: начало и конец совпадают, и браузер не
  // рисует ничего. Единственный маршрут — самый обычный случай.
  test("a single route draws a full ring instead of nothing", () => {
    const d = describeDonutSegment(0, 1)
    expect(d).not.toMatch(/M0,-115A115,115,0,1,1,0,-115/)
    expect(d.length).toBeGreaterThan(20)
  })
})

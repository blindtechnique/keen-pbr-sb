import { describe, expect, test } from "bun:test"

import {
  buildTrafficSeries,
  findNearestTrafficSampleIndex,
  formatBitRate,
  formatTrafficBytes,
  TRAFFIC_CHART_WIDTH,
  trafficTooltipTop,
} from "../src/components/transports/interface-traffic-model"

describe("interface traffic presentation", () => {
  test("builds finite bounded SVG points from both series", () => {
    const history = Array.from({ length: 140 }, (_, index) => ({
      age_ms: (139 - index) * 2000,
      rx_bits_per_second: index * 100,
      tx_bits_per_second: index % 2 === 0 ? index * 50 : Number.NaN,
    }))

    const series = buildTrafficSeries({
      history,
    })

    expect(series.rx.split(" ")).toHaveLength(120)
    expect(series.tx.split(" ")).toHaveLength(120)
    expect(series.rx).not.toContain("NaN")
    expect(series.tx).not.toContain("Infinity")
  })

  test("formats current rates and byte totals without a chart dependency", () => {
    expect(formatBitRate(4_180, "ru-RU")).toBe("4,18 кбит/с")
    expect(formatBitRate(undefined, "ru-RU")).toBe("—")
    expect(formatTrafficBytes(3 * 1024 ** 3, "ru-RU")).toBe("3 ГБ")
    expect(formatTrafficBytes(1536, "en-US")).toBe("1.5 KB")
  })

  test("clamps invalid source values to the graph baseline", () => {
    const series = buildTrafficSeries({
      history: [
        {
          age_ms: 2000,
          rx_bits_per_second: -1,
          tx_bits_per_second: Number.POSITIVE_INFINITY,
        },
        {
          age_ms: 0,
          rx_bits_per_second: 0,
          tx_bits_per_second: 0,
        },
      ],
    })

    expect(series.rx).toBe("0.00,162.00 744.00,162.00")
    expect(series.tx).toBe("0.00,162.00 744.00,162.00")
  })

  test("preserves real sampling gaps on the horizontal axis", () => {
    const series = buildTrafficSeries({
      history: [
        {
          age_ms: 10_000,
          rx_bits_per_second: 1,
          tx_bits_per_second: 1,
        },
        {
          age_ms: 2_000,
          rx_bits_per_second: 1,
          tx_bits_per_second: 1,
        },
        {
          age_ms: 0,
          rx_bits_per_second: 1,
          tx_bits_per_second: 1,
        },
      ],
    })

    expect(series.rx).toBe("0.00,0.00 595.20,0.00 744.00,0.00")
  })

  test("rounds the chart ceiling and derives sample timestamps", () => {
    const series = buildTrafficSeries({
      sampled_at_unix_ms: 20_000,
      history: [
        {
          age_ms: 10_000,
          rx_bits_per_second: 18_000,
          tx_bits_per_second: 1_000,
        },
        {
          age_ms: 0,
          rx_bits_per_second: 20_001,
          tx_bits_per_second: 2_000,
        },
      ],
    })

    expect(series.maximum).toBe(50_000)
    expect(series.oldestSampledAt).toBe(10_000)
    expect(series.newestSampledAt).toBe(20_000)
    expect(series.rxArea.startsWith("M 0 162 L ")).toBe(true)
    expect(series.samples).toEqual([
      {
        x: 0,
        rxY: 103.68,
        txY: 158.76,
        rxBitsPerSecond: 18_000,
        txBitsPerSecond: 1_000,
        sampledAtUnixMs: 10_000,
      },
      {
        x: TRAFFIC_CHART_WIDTH,
        rxY: 97.19676,
        txY: 155.52,
        rxBitsPerSecond: 20_001,
        txBitsPerSecond: 2_000,
        sampledAtUnixMs: 20_000,
      },
    ])
  })

  test("finds the nearest retained sample for hover and keyboard cursors", () => {
    const series = buildTrafficSeries({
      sampled_at_unix_ms: 30_000,
      history: [
        {
          age_ms: 20_000,
          rx_bits_per_second: 1_000,
          tx_bits_per_second: 2_000,
        },
        {
          age_ms: 5_000,
          rx_bits_per_second: 3_000,
          tx_bits_per_second: 4_000,
        },
        {
          age_ms: 0,
          rx_bits_per_second: 5_000,
          tx_bits_per_second: 6_000,
        },
      ],
    })

    expect(findNearestTrafficSampleIndex(series.samples, -20)).toBe(0)
    expect(findNearestTrafficSampleIndex(series.samples, 400)).toBe(1)
    expect(
      findNearestTrafficSampleIndex(series.samples, TRAFFIC_CHART_WIDTH + 20)
    ).toBe(2)
    expect(findNearestTrafficSampleIndex([], 100)).toBeUndefined()
    expect(
      findNearestTrafficSampleIndex(series.samples, Number.NaN)
    ).toBeUndefined()
    expect(series.samples[1]).toMatchObject({
      rxBitsPerSecond: 3_000,
      txBitsPerSecond: 4_000,
      sampledAtUnixMs: 25_000,
    })
  })

  test("tracks the pointer and clamps the tooltip inside its overlay area", () => {
    expect(trafficTooltipTop(10, 78, 191)).toBe(26)
    expect(trafficTooltipTop(80, 78, 191)).toBe(96)
    expect(trafficTooltipTop(100, 78, 191)).toBe(113)
    expect(trafficTooltipTop(150, 78, 191)).toBe(113)
    expect(trafficTooltipTop(-20, 78, 191)).toBe(16)
    expect(trafficTooltipTop(100, 500, 191)).toBe(0)
  })
})

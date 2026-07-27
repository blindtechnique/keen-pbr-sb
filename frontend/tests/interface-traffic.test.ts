import { describe, expect, test } from "bun:test"

import {
  buildTrafficSeries,
  formatBitRate,
  formatTrafficBytes,
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
  })
})

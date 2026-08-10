import { describe, expect, test } from "bun:test"

import { applyInterfaceTrafficUpdate } from "../src/api/status-event-cache"
import type { RuntimeInterfaceInventoryResponse } from "../src/api/generated/model"

const inventory = (): RuntimeInterfaceInventoryResponse => ({
  interfaces: [
    { name: "nwg1", status: "up" },
    { name: "nwg2", status: "up" },
  ],
})

describe("per-interface measurement freshness", () => {
  test("each interface keeps the instant IT was read, not the batch's", () => {
    // One compact batch, two interfaces read a measurable moment apart. Before
    // this, both were stamped with the batch value and a stalled interface was
    // indistinguishable from a live one.
    const merged = applyInterfaceTrafficUpdate(inventory(), {
      sampled_at_unix_ms: 5_000,
      interfaces: [
        {
          name: "nwg1",
          available: true,
          reset: false,
          rx_bytes: 1,
          tx_bytes: 2,
          observed_at_unix_ms: 4_100,
        },
        {
          name: "nwg2",
          available: true,
          reset: false,
          rx_bytes: 3,
          tx_bytes: 4,
          observed_at_unix_ms: 4_900,
        },
      ],
    })

    expect(merged.interfaces[0]?.traffic?.sampled_at_unix_ms).toBe(4_100)
    expect(merged.interfaces[1]?.traffic?.sampled_at_unix_ms).toBe(4_900)
  })

  test("falls back to the batch stamp for a daemon that predates the field", () => {
    const merged = applyInterfaceTrafficUpdate(inventory(), {
      sampled_at_unix_ms: 5_000,
      interfaces: [
        { name: "nwg1", available: true, reset: false, rx_bytes: 1, tx_bytes: 2 },
      ],
    })

    expect(merged.interfaces[0]?.traffic?.sampled_at_unix_ms).toBe(5_000)
  })

  test("history ages by this interface's own elapsed time", () => {
    const first = applyInterfaceTrafficUpdate(inventory(), {
      sampled_at_unix_ms: 1_000,
      interfaces: [
        {
          name: "nwg1",
          available: true,
          reset: false,
          rx_bytes: 1,
          tx_bytes: 1,
          rx_bits_per_second: 10,
          tx_bits_per_second: 20,
          observed_at_unix_ms: 1_000,
        },
      ],
    })

    // The batch is dispatched 5s later, but this interface was read 2s after
    // its previous reading. Ageing by the batch delta would slide the whole
    // graph of a slow-sampled interface along a clock that is not its own.
    const second = applyInterfaceTrafficUpdate(first, {
      sampled_at_unix_ms: 6_000,
      interfaces: [
        {
          name: "nwg1",
          available: true,
          reset: false,
          rx_bytes: 2,
          tx_bytes: 2,
          rx_bits_per_second: 30,
          tx_bits_per_second: 40,
          observed_at_unix_ms: 3_000,
        },
      ],
    })

    const history = second.interfaces[0]?.traffic?.history
    expect(history?.length).toBe(2)
    expect(history?.[0]?.age_ms).toBe(2_000)
    expect(history?.[1]?.age_ms).toBe(0)
  })

  test("an unavailable interface reports no traffic at all", () => {
    const merged = applyInterfaceTrafficUpdate(inventory(), {
      sampled_at_unix_ms: 5_000,
      interfaces: [{ name: "nwg1", available: false, reset: false }],
    })

    // No stamp is better than a fresh-looking one: the counters were not read.
    expect(merged.interfaces[0]?.traffic).toBeUndefined()
  })
})

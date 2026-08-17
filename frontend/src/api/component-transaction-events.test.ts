import { readFileSync } from "node:fs"
import { join } from "node:path"

import { afterEach, describe, expect, test } from "bun:test"

import {
  applyComponentTransactionStatusEvent,
  getComponentTransactionProgress,
  resetComponentTransactionProgress,
  subscribeComponentTransaction,
} from "./component-transaction-events"

afterEach(() => {
  resetComponentTransactionProgress()
})

const frame = (data: unknown) =>
  JSON.stringify({ type: "component_transaction", data })

const step = (overrides: Record<string, unknown> = {}) => ({
  component: "nfqws2-keenetic",
  operation: "upgrade",
  step: "install",
  active: true,
  detail: "",
  ...overrides,
})

describe("applyComponentTransactionStatusEvent", () => {
  test("accepts a well-formed progress frame", () => {
    expect(applyComponentTransactionStatusEvent(frame(step()))).toBe(true)
    expect(getComponentTransactionProgress()?.step).toBe("install")
  })

  test("a finished operation stops being progress", () => {
    applyComponentTransactionStatusEvent(frame(step()))
    applyComponentTransactionStatusEvent(
      frame(step({ step: "finished", active: false }))
    )
    // Not "progress that says finished forever": the dialog keys off presence.
    expect(getComponentTransactionProgress()).toBeNull()
  })

  test("rejects frames it cannot trust", () => {
    expect(applyComponentTransactionStatusEvent("not json")).toBe(false)
    expect(applyComponentTransactionStatusEvent(JSON.stringify({}))).toBe(false)
    expect(
      applyComponentTransactionStatusEvent(
        JSON.stringify({ type: "list_refresh", data: step() })
      )
    ).toBe(false)
    // A frame from a newer backend whose shape means something else must be
    // ignored, not rendered as a step this page invented.
    expect(
      applyComponentTransactionStatusEvent(frame(step({ active: "yes" })))
    ).toBe(false)
    expect(applyComponentTransactionStatusEvent(frame(step({ step: 7 })))).toBe(
      false
    )
    expect(getComponentTransactionProgress()).toBeNull()
  })

  test("a malformed frame does not discard progress already shown", () => {
    applyComponentTransactionStatusEvent(frame(step()))
    applyComponentTransactionStatusEvent("{")
    expect(getComponentTransactionProgress()?.step).toBe("install")
  })

  test("a new subscriber is told the current state immediately", () => {
    applyComponentTransactionStatusEvent(frame(step({ step: "verify" })))
    let seen: string | null = null
    const stop = subscribeComponentTransaction((progress) => {
      seen = progress?.step ?? null
    })
    // A component mounted after the frame arrived would otherwise never learn
    // an operation is in flight.
    expect(seen).toBe("verify")
    stop()
  })
})

describe("the page's step map", () => {
  test("covers every step the handler publishes", () => {
    const handler = readFileSync(
      join(
        import.meta.dir,
        "..",
        "..",
        "..",
        "src",
        "api",
        "handler_nfqws.cpp",
      ),
      "utf8",
    )
    const published = new Set<string>()
    for (const match of handler.matchAll(/progress\.step\("([a-z_]+)"\)/g)) {
      published.add(match[1])
    }
    expect(published.size).toBeGreaterThan(3)

    const page = readFileSync(
      join(import.meta.dir, "..", "pages", "nfqws-page.tsx"),
      "utf8",
    )
    const mapped = new Set<string>()
    const block = page.slice(
      page.indexOf("const progressStepKeys"),
      page.indexOf("}", page.indexOf("const progressStepKeys")),
    )
    for (const match of block.matchAll(/^\s{2}([a-z_]+):/gm)) {
      mapped.add(match[1])
    }

    // A step the backend sends and the page cannot name shows nothing at all,
    // which is a silent hole in exactly the display an operator is watching.
    for (const name of published) {
      expect([...mapped]).toContain(name)
    }
  })
})

import { describe, expect, test } from "bun:test"
import { FieldApi, FormApi } from "@tanstack/react-form"
import {
  getDnsLearning,
  withDnsLearning,
  interceptionState,
} from "../src/lib/dns-learning"
import { InterceptionState } from "../src/api/generated/model/interceptionState"
import type { DnsConfig } from "../src/api/generated/model/dnsConfig"

describe("independent DNS/L7 learning settings", () => {
  test("defaults off; missing/null fields inherit the legacy switch", () => {
    expect(getDnsLearning(undefined)).toEqual({ dns: false, l7: false })
    expect(getDnsLearning({ passive_learning: true })).toEqual({
      dns: true,
      l7: true,
    })
    expect(
      getDnsLearning({
        passive_learning: true,
        learning: { dns: false, l7: null },
      })
    ).toEqual({ dns: false, l7: true })
    expect(getDnsLearning({ learning: { l7: true } })).toEqual({
      dns: false,
      l7: true,
    })
  })
  test("unrelated Save preserves legacy, null and extension fields", () => {
    for (const dns of [
      undefined,
      {},
      { passive_learning: null },
      { passive_learning: true, learning: { dns: null, future: "keep" } },
    ]) {
      expect(withDnsLearning(dns, getDnsLearning(dns))).toEqual({ ...dns })
    }
  })
  test("only an explicitly changed effective value is written", () => {
    const original: DnsConfig = {
      passive_learning: true,
      future: 42,
      learning: { l7: null, future: "keep" },
      fallback: ["primary"],
    }
    const next = withDnsLearning(original, { dns: false, l7: true })
    expect(next).toEqual({
      ...original,
      learning: { ...original.learning, dns: false },
    })
    expect(original.learning?.dns).toBeUndefined()
    expect(getDnsLearning(next)).toEqual({ dns: false, l7: true })
  })
  test("restoring the toggle clears semantic dirty without a config write", () => {
    const form = new FormApi({ defaultValues: { dns: false, l7: true } })
    const field = new FieldApi({ form, name: "dns" })
    const unmount = form.mount()
    const unmountField = field.mount()
    form.setFieldValue("dns", true)
    expect(form.state.isDefaultValue).toBe(false)
    form.setFieldValue("dns", false)
    expect(form.state.isDefaultValue).toBe(true)
    unmountField()
    unmount()
  })
})

test("unknown diagnostics never become a failed VPN or an active learner", () => {
  for (const input of [undefined, null, "", "down", "working", "future"])
    expect(interceptionState(input)).toBe("unknown")
  for (const state of Object.values(InterceptionState))
    expect(interceptionState(state)).toBe(state)
})

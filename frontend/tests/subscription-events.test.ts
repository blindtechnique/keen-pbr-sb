import { describe, expect, test } from "bun:test"
import { QueryClient } from "@tanstack/react-query"
import {
  applySubscriptionStatusEvent,
  SUBSCRIPTION_CHANGE_QUERY_KEYS,
} from "@/api/subscription-events"

describe("subscription change SSE", () => {
  test("one credential-free event invalidates the existing subscription, bell and routing caches", () => {
    const client = new QueryClient()
    for (const queryKey of SUBSCRIPTION_CHANGE_QUERY_KEYS)
      client.setQueryData(queryKey, { existing: true })
    client.setQueryData(["unrelated"], { unchanged: true })
    expect(
      applySubscriptionStatusEvent(
        client,
        JSON.stringify({ type: "subscriptions" })
      )
    ).toBe(true)
    for (const queryKey of SUBSCRIPTION_CHANGE_QUERY_KEYS) {
      expect(client.getQueryState(queryKey)?.isInvalidated).toBe(true)
      expect(client.getQueryData(queryKey)).toEqual({ existing: true })
    }
    expect(client.getQueryState(["unrelated"])?.isInvalidated).toBe(false)
    client.clear()
  })

  test("unrelated and malformed events do not invalidate subscription state", () => {
    const client = new QueryClient()
    const queryKey = SUBSCRIPTION_CHANGE_QUERY_KEYS[0]
    client.setQueryData(queryKey, { existing: true })
    for (const raw of ["not json", "null", "[]", "{}", '{"type":"service"}']) {
      expect(applySubscriptionStatusEvent(client, raw)).toBe(false)
    }
    expect(client.getQueryState(queryKey)?.isInvalidated).toBe(false)
    client.clear()
  })
})

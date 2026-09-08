import { describe, expect, test } from "bun:test"

import {
  DEFAULT_SUBSCRIPTION_REFRESH_SECONDS,
  SUBSCRIPTION_REFRESH_PRESETS,
  readSubscriptionDeepLink,
  subscriptionCardId,
  subscriptionRefreshDraft,
  subscriptionRefreshSeconds,
  withoutSubscriptionDeepLink,
} from "../src/components/transports/subscription-settings-model"
import {
  initialNewServerLines,
  initialSelectedLines,
} from "../src/components/transports/subscription-import-model"
import type { SubscriptionPreviewCandidate } from "../src/api/generated/model"

describe("subscription refresh settings", () => {
  test("keeps the six-hour default and supports disabling refresh", () => {
    expect(subscriptionRefreshSeconds(subscriptionRefreshDraft())).toBe(
      DEFAULT_SUBSCRIPTION_REFRESH_SECONDS
    )
    for (const seconds of SUBSCRIPTION_REFRESH_PRESETS) {
      expect(
        subscriptionRefreshSeconds(subscriptionRefreshDraft(seconds))
      ).toBe(seconds)
    }
  })

  test("custom hours stay within the daemon's interval bounds", () => {
    expect(
      subscriptionRefreshSeconds({ interval: "custom", customHours: "1" })
    ).toBe(3_600)
    expect(
      subscriptionRefreshSeconds({ interval: "custom", customHours: "168" })
    ).toBe(604_800)
    for (const value of ["", " ", "0", "-1", "1.5", "169", "Infinity", "NaN"]) {
      expect(
        subscriptionRefreshSeconds({ interval: "custom", customHours: value })
      ).toBeUndefined()
    }
  })

  test("renaming preserves a non-preset interval without rounding it", () => {
    expect(subscriptionRefreshSeconds(subscriptionRefreshDraft(5_401))).toBe(
      5_401
    )
    expect(
      subscriptionRefreshSeconds({ interval: "3600.5", customHours: "" })
    ).toBeUndefined()
    expect(
      subscriptionRefreshSeconds({ interval: "", customHours: "" })
    ).toBeUndefined()
  })
})

describe("subscription notice navigation", () => {
  test("opens only the requested subscriptions tab and decodes its exact ID", () => {
    expect(
      readSubscriptionDeepLink("?tab=subscriptions&subscription=plan%2B1")
    ).toEqual({ open: true, id: "plan+1" })
    expect(readSubscriptionDeepLink("tab=subscriptions")).toEqual({
      open: true,
      id: undefined,
    })
    expect(readSubscriptionDeepLink("tab=all&subscription=plan")).toEqual({
      open: false,
      id: undefined,
    })
    expect(subscriptionCardId("plan+1")).toBe("subscription-plan%2B1")
  })

  test("manual tab selection removes only the subscription navigation hint", () => {
    expect(
      withoutSubscriptionDeepLink(
        "https://panel.test/transports?tab=subscriptions&subscription=one&catalog=work#all"
      )
    ).toBe("https://panel.test/transports?catalog=work#all")
    expect(
      withoutSubscriptionDeepLink(
        "https://panel.test/transports?tab=all&catalog=work#all"
      )
    ).toBe("https://panel.test/transports?tab=all&catalog=work#all")
  })
})

describe("new-server preview selection", () => {
  test("preselects ready new entries within the existing batch size, not conflicts", () => {
    const candidates: SubscriptionPreviewCandidate[] = Array.from(
      { length: 12 },
      (_, index) => ({
        line: index + 1,
        disposition:
          index === 1
            ? "tag_conflict"
            : index === 2
              ? "already_configured"
              : "importable",
      })
    )
    expect([...initialNewServerLines(candidates)]).toEqual([
      1, 4, 5, 6, 7, 8, 9, 10,
    ])
    expect([...initialSelectedLines(candidates)]).toEqual([1])
  })
})

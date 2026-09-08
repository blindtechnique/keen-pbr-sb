export const SUBSCRIPTION_REFRESH_PRESETS = [
  0, 3_600, 21_600, 43_200, 86_400,
] as const
export const DEFAULT_SUBSCRIPTION_REFRESH_SECONDS = 21_600

export type SubscriptionRefreshDraft = {
  interval: string
  customHours: string
}

export function subscriptionRefreshDraft(
  seconds = DEFAULT_SUBSCRIPTION_REFRESH_SECONDS
): SubscriptionRefreshDraft {
  return {
    interval: String(seconds),
    customHours: String(
      (seconds || DEFAULT_SUBSCRIPTION_REFRESH_SECONDS) / 3_600
    ),
  }
}

export function subscriptionRefreshSeconds(
  draft: SubscriptionRefreshDraft
): number | undefined {
  if (draft.interval === "custom") {
    const hours = Number(draft.customHours.trim())
    return draft.customHours.trim() &&
      Number.isInteger(hours) &&
      hours >= 1 &&
      hours <= 168
      ? hours * 3_600
      : undefined
  }
  // Preserve a valid existing non-preset interval exactly when only the name
  // is edited; it may have been configured through the API in seconds.
  const seconds = Number(draft.interval)
  return draft.interval.trim() &&
    Number.isInteger(seconds) &&
    (seconds === 0 || (seconds >= 3_600 && seconds <= 604_800))
    ? seconds
    : undefined
}

export function readSubscriptionDeepLink(search: string): {
  open: boolean
  id?: string
} {
  const params = new URLSearchParams(search)
  const open = params.get("tab") === "subscriptions"
  return {
    open,
    id: open ? params.get("subscription") || undefined : undefined,
  }
}

export function withoutSubscriptionDeepLink(href: string): string {
  const url = new URL(href)
  if (url.searchParams.get("tab") === "subscriptions") {
    url.searchParams.delete("tab")
    url.searchParams.delete("subscription")
  }
  return url.href
}

export function subscriptionCardId(id: string): string {
  return `subscription-${encodeURIComponent(id)}`
}

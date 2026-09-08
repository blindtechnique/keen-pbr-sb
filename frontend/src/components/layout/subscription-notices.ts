import type { SubscriptionNotice } from "@/api/generated/model"
import type { Notice } from "@/components/layout/notifications"

type Translate = (key: string, options?: Record<string, unknown>) => string

export function presentSubscriptionNotice(
  notice: SubscriptionNotice,
  t: Translate
): Notice | undefined {
  const options = {
    name: notice.name,
    count: notice.count,
    days: notice.days,
    percent: notice.remaining_percent,
  }
  const common = {
    id: notice.id,
    href: `/transports?tab=subscriptions&subscription=${encodeURIComponent(notice.subscription_id)}`,
    actionLabel: t("notifications.subscriptions.open"),
  }
  switch (notice.kind) {
    case "new_servers":
      return {
        ...common,
        level: "info",
        text: t(
          notice.count === undefined
            ? "notifications.subscriptions.newServers"
            : "notifications.subscriptions.newServersCount",
          options
        ),
        actionLabel: t("notifications.subscriptions.chooseServers"),
      }
    case "traffic_low":
      return {
        ...common,
        level: "warning",
        text: t(
          notice.remaining_percent === undefined
            ? "notifications.subscriptions.trafficLow"
            : "notifications.subscriptions.trafficRemaining",
          options
        ),
      }
    case "traffic_exhausted":
      return {
        ...common,
        level: "warning",
        text: t("notifications.subscriptions.trafficExhausted", options),
      }
    case "expires_soon":
      return {
        ...common,
        level: "warning",
        text: t(
          notice.days === undefined
            ? "notifications.subscriptions.expiresSoon"
            : "notifications.subscriptions.expiresInDays",
          options
        ),
      }
    case "expired":
      return {
        ...common,
        level: "warning",
        text: t("notifications.subscriptions.expired", options),
      }
    case "sync_failed":
      return {
        ...common,
        level: "error",
        text: t("notifications.subscriptions.syncFailed", options),
      }
  }
}

// Clearing the bell acknowledges the full loaded batch, not only the twenty
// rows rendered in the popover. A later revision remains a different ID.
export function notificationUpdateIds(
  displayedNotices: readonly Notice[],
  subscriptionNotices: readonly SubscriptionNotice[]
): string[] {
  return [
    ...new Set([
      ...displayedNotices
        .filter((notice) => notice.timestamp === undefined)
        .map((notice) => notice.id),
      ...subscriptionNotices.map((notice) => notice.id),
    ]),
  ]
}

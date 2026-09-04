import type { SavedSubscription } from "@/api/generated/model"

export function subscriptionUsage(
  subscription: SavedSubscription,
  now = Date.now()
) {
  const {
    upload_bytes: upload,
    download_bytes: download,
    total_bytes: total,
    expires_at: expires,
  } = subscription
  const used =
    upload !== undefined && download !== undefined
      ? upload + download
      : undefined
  return {
    used,
    remaining:
      total !== undefined && used !== undefined
        ? Math.max(0, total - used)
        : undefined,
    percent:
      total !== undefined && total > 0 && used !== undefined
        ? Math.min(100, Math.max(0, (used / total) * 100))
        : undefined,
    days: expires
      ? Math.max(0, Math.ceil((expires * 1000 - now) / 86_400_000))
      : undefined,
    expired: Boolean(expires && expires * 1000 <= now),
  }
}

export function subscriptionBytes(value: number, locale: string) {
  const units = [
    "byte",
    "kilobyte",
    "megabyte",
    "gigabyte",
    "terabyte",
  ] as const
  let index = 0
  while (value >= 1000 && index < units.length - 1) {
    value /= 1000
    index++
  }
  return new Intl.NumberFormat(locale, {
    style: "unit",
    unit: units[index],
    maximumFractionDigits: 1,
  }).format(value)
}

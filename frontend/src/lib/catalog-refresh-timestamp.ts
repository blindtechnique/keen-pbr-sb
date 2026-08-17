export type CatalogRefreshTimestampFormatOptions = Readonly<{
  locale?: string
  timeZone?: string
}>

export function formatCatalogRefreshTimestamp(
  epochSeconds: number | undefined,
  options: CatalogRefreshTimestampFormatOptions = {}
): string | null {
  if (
    typeof epochSeconds !== "number" ||
    !Number.isFinite(epochSeconds) ||
    epochSeconds <= 0
  ) {
    return null
  }

  const date = new Date(epochSeconds * 1000)
  if (Number.isNaN(date.getTime())) {
    return null
  }

  return new Intl.DateTimeFormat(options.locale, {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
    ...(options.timeZone ? { timeZone: options.timeZone } : {}),
  }).format(date)
}

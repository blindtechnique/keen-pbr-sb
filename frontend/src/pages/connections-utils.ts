type Translate = (
  key: string,
  options?: Record<string, unknown>
) => string

/**
 * Only closed connections get an age. Use the backend snapshot timestamp so
 * rendering stays deterministic and all rows from one snapshot share a clock.
 */
export function formatLastSeen(
  lastSeen: number,
  snapshotAt: number,
  t: Translate
): string {
  if (!lastSeen || !snapshotAt) {
    return ""
  }

  const seconds = Math.max(0, snapshotAt - lastSeen)
  if (seconds < 10) {
    return t("connections.age.now")
  }
  if (seconds < 60) {
    return t("connections.age.seconds", { count: seconds })
  }
  if (seconds < 3600) {
    return t("connections.age.minutes", { count: Math.floor(seconds / 60) })
  }
  return t("connections.age.hours", { count: Math.floor(seconds / 3600) })
}

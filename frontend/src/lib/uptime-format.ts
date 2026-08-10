type Translate = (key: string, options?: Record<string, unknown>) => string

/**
 * Renders a duration in whole days, hours and minutes.
 *
 * Kept separate from the router card's own formatter on purpose: router,
 * daemon, routing-runtime and interface uptimes are four different quantities
 * that reset for unrelated reasons, and sharing a label between them is how a
 * reader ends up believing a tunnel has been up since the router booted.
 */
export function formatUptimeSeconds(seconds: number, t: Translate): string {
  if (!Number.isFinite(seconds) || seconds < 60) {
    return t("common.uptime.lessThanMinute")
  }

  const days = Math.floor(seconds / 86_400)
  const hours = Math.floor((seconds % 86_400) / 3_600)
  const minutes = Math.floor((seconds % 3_600) / 60)

  if (days > 0) {
    return t("common.uptime.days", { days, hours, minutes })
  }
  if (hours > 0) {
    return t("common.uptime.hours", { hours, minutes })
  }
  return t("common.uptime.minutes", { minutes })
}

/**
 * Renders how long ago an absolute up-transition happened.
 *
 * `upSinceUnixMs` is an anchor rather than a duration precisely so that a UI
 * refresh cannot restart it, so the elapsed time is derived here at render
 * time. `null`/`undefined` means the backend has no confirmed transition and
 * MUST be rendered as unknown - substituting any other uptime we happen to
 * have would report a number that silently resets for the wrong reasons.
 */
export function formatUptimeSince(
  upSinceUnixMs: number | null | undefined,
  t: Translate,
  nowMs: number = Date.now()
): string {
  if (typeof upSinceUnixMs !== "number" || !Number.isFinite(upSinceUnixMs)) {
    return t("common.uptime.unknown")
  }

  const elapsedSeconds = (nowMs - upSinceUnixMs) / 1_000
  if (elapsedSeconds < 0) {
    // The daemon's wall clock and the browser's disagree, most often right
    // after an NTP step. Reporting a negative age would be worse than
    // rounding the transition to "just now".
    return t("common.uptime.lessThanMinute")
  }

  return formatUptimeSeconds(elapsedSeconds, t)
}

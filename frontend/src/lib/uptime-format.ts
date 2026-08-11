type Translate = (key: string, options?: Record<string, unknown>) => string

function pad2(value: number): string {
  return value < 10 ? `0${value}` : String(value)
}

/**
 * Renders a duration the way KeeneticOS renders one: HH:MM:SS, with a day
 * count in front once it passes twenty-four hours.
 *
 * Matching the firmware's own format is the point. This number sits next to
 * values the router itself displays, and a second convention beside them makes
 * the reader stop and work out whether the two mean the same thing.
 */
export function formatUptimeSeconds(seconds: number, t: Translate): string {
  const total = Number.isFinite(seconds) ? Math.max(0, Math.floor(seconds)) : 0

  const days = Math.floor(total / 86_400)
  const clock = [
    pad2(Math.floor((total % 86_400) / 3_600)),
    pad2(Math.floor((total % 3_600) / 60)),
    pad2(total % 60),
  ].join(":")

  return days > 0 ? t("common.uptime.withDays", { days, clock }) : clock
}

/**
 * Renders how long ago an absolute up-transition happened.
 *
 * `upSinceUnixMs` is an anchor rather than a duration precisely so that a UI
 * refresh cannot restart it, so the elapsed time is derived here at render
 * time. `null`/`undefined` means the backend has no confirmed transition and
 * MUST be rendered as unknown - substituting any other uptime we happen to
 * have would report a number that silently resets for the wrong reasons.
 *
 * `nowMs` must be on the ROUTER's clock, since `upSinceUnixMs` is. Callers get
 * one from routerNowMs(); passing the browser's own clock would measure the
 * disagreement between two machines instead of an elapsed time.
 */
export function formatUptimeSince(
  upSinceUnixMs: number | null | undefined,
  t: Translate,
  nowMs: number
): string {
  if (typeof upSinceUnixMs !== "number" || !Number.isFinite(upSinceUnixMs)) {
    return t("common.uptime.unknown")
  }

  // A negative age means the two clocks still disagree despite the correction,
  // most often in the moments right after an NTP step. Clamping to zero shows
  // "just now" instead of a nonsensical countdown; formatUptimeSeconds floors
  // at zero for exactly this.
  return formatUptimeSeconds((nowMs - upSinceUnixMs) / 1_000, t)
}

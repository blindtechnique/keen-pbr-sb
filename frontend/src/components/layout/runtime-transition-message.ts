// Log compatibility for older releases. Match the whole runtime transition,
// never a nested "start requested" phrase in an actual failure detail.
type RuntimeTransitionMessageKind =
  | "unverified"
  | "failed"
  | "startFailed"
  | "progress"

export function getRuntimeTransitionMessageKind(
  text: string
): RuntimeTransitionMessageKind | undefined {
  const match =
    /^Runtime state (stopped|starting|running|applying|restart_required|broken|shutting_down) -> (stopped|starting|running|applying|restart_required|broken|shutting_down): ([^\r\n]+)$/.exec(
      text.trim()
    )
  if (!match) return undefined
  const [, , next, reason] = match
  if (next === "broken") {
    if (reason === "configuration generation terminal is unknown") {
      return "unverified"
    }
    if (reason === "runtime start failed") return "startFailed"
    return "failed"
  }
  if (
    next === "starting" &&
    (reason === "runtime start requested" ||
      reason === "cold-boot recovery attempt admitted" ||
      reason === "stopped configuration bootstrap started")
  ) {
    return "progress"
  }
  if (
    next === "running" &&
    (reason === "runtime start complete" ||
      reason === "cold-boot publication complete" ||
      reason === "stopped configuration bootstrap complete")
  ) {
    return "progress"
  }
  if (next === "stopped" && reason === "daemon shutdown cleanup verified") {
    return "progress"
  }
  return undefined
}

export function isRuntimeTransitionProgress(text: string): boolean {
  return getRuntimeTransitionMessageKind(text) === "progress"
}

export type SoftwareUpdateDialogContent = "release-notes" | "update-log"

// Keep the server's diagnostic body alongside the legacy Error message. The
// shared presenter reads only known error fields; request/polling behavior is
// deliberately owned by SoftwareUpdateCard, not this presentation adapter.
export function softwareUpdateResponseError(
  status: number,
  body: { error?: string }
) {
  return Object.assign(new Error(body.error ?? `HTTP ${status}`), {
    status,
    details: body,
  })
}

type SoftwareUpdateRuntime = {
  running?: boolean
}

export function getSoftwareUpdateDialogContent(
  status: SoftwareUpdateRuntime | null | undefined,
  updateAttemptStarted: boolean
): SoftwareUpdateDialogContent {
  return status?.running || updateAttemptStarted
    ? "update-log"
    : "release-notes"
}

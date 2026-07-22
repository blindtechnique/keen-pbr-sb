export type SoftwareUpdateDialogContent = "release-notes" | "update-log"

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

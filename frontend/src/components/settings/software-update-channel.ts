import type {
  SystemUpdateRequest,
  SystemUpdateStatus,
} from "@/api/generated/model"

export function softwareUpdateRequest(
  status: Partial<
    Pick<
      SystemUpdateStatus,
      | "installable"
      | "check_error"
      | "current_ahead"
      | "running"
      | "latest"
      | "release_tag"
      | "channel"
    >
  > | null
): SystemUpdateRequest | null {
  if (
    !status?.installable ||
    status.check_error ||
    status.current_ahead ||
    status.running ||
    !status.latest ||
    !status.release_tag ||
    (status.channel !== "stable" && status.channel !== "alpha")
  )
    return null
  return {
    channel: status.channel,
    release_tag: status.release_tag,
    version: status.latest,
  }
}

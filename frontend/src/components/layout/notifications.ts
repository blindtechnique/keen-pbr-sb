import type { NfqwsUpdateStatus } from "@/api/nfqws"

export type SoftwareUpdateResponse = {
  available?: boolean
  latest?: string
}

export type Notice = {
  id: string
  level: "error" | "warning" | "info"
  text: string
  timestamp?: string
}

type Translate = (key: string, options?: Record<string, unknown>) => string

const MAX_NOTICES = 20

export function collectNotices(
  lines: string[],
  softwareUpdate: SoftwareUpdateResponse | undefined,
  nfqwsUpdate: NfqwsUpdateStatus | undefined,
  dismissedUntil: number,
  dismissedIds: ReadonlySet<string>,
  t: Translate
): Notice[] {
  const notices: Notice[] = []

  addSyntheticNotice(
    notices,
    softwareUpdate?.available && softwareUpdate.latest
      ? {
          id: `system-update-${softwareUpdate.latest}`,
          level: "info",
          text: t("notifications.updateAvailable", {
            version: softwareUpdate.latest,
          }),
        }
      : undefined,
    dismissedIds
  )

  const nfqwsInstalled =
    nfqwsUpdate?.installed ??
    Boolean(nfqwsUpdate?.current && nfqwsUpdate.current.trim())
  addSyntheticNotice(
    notices,
    nfqwsInstalled && nfqwsUpdate?.available && nfqwsUpdate.latest
      ? {
          id: `nfqws-update-${nfqwsUpdate.latest}`,
          level: "info",
          text: t("notifications.nfqwsUpdateAvailable", {
            version: nfqwsUpdate.latest,
          }),
        }
      : undefined,
    dismissedIds
  )

  // Newest first: the tail of the file is the most recent.
  for (let index = lines.length - 1; index >= 0; index -= 1) {
    if (notices.length >= MAX_NOTICES) {
      break
    }
    const line = lines[index]
    const match = line.match(/^(\S+ \S+)\s+\[([EW])\]\s+(.*)$/)
    if (!match) {
      continue
    }
    const [, timestamp, marker, text] = match
    // The log keeps its history; dismissing only hides what was already read.
    if (
      dismissedUntil > 0 &&
      Date.parse(timestamp.replace(" ", "T")) <= dismissedUntil
    ) {
      continue
    }
    notices.push({
      id: `${timestamp}-${index}`,
      level: marker === "E" ? "error" : "warning",
      text,
      timestamp,
    })
  }

  return notices
}

function addSyntheticNotice(
  notices: Notice[],
  notice: Notice | undefined,
  dismissedIds: ReadonlySet<string>
) {
  if (notice && !dismissedIds.has(notice.id)) {
    notices.push(notice)
  }
}

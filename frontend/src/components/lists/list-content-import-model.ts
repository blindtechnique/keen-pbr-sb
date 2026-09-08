import type { ListContentImportRequest } from "@/api/generated/model/listContentImportRequest"
import type { ListContentImportResponse } from "@/api/generated/model/listContentImportResponse"

export type ListContentFormat = NonNullable<ListContentImportRequest["format"]>
export const LIST_CONTENT_MAX_BYTES = 2 * 1024 * 1024
export type ListImportSession = { current: symbol | null }
export type ListImportAdded = {
  domains: number
  ipCidrs: number
  duplicates: number
}
export type ListContentImportState =
  | { status: "idle" | "reading" | "pending" }
  | { status: "failed"; reason: "tooLarge" | "readFailed" | "requestFailed" }
  | { status: "invalid"; result: ListContentImportResponse }
  | { status: "added"; added: ListImportAdded }

export function listContentTextTooLarge(text: string): boolean {
  return (
    text.length > LIST_CONTENT_MAX_BYTES ||
    new TextEncoder().encode(text).byteLength > LIST_CONTENT_MAX_BYTES
  )
}

export async function readListContentFile(
  session: ListImportSession,
  file: Pick<File, "size" | "text">,
  setText: (text: string) => void,
  publish: (state: ListContentImportState) => void
): Promise<void> {
  const token = Symbol("list-file")
  session.current = token
  if (file.size > LIST_CONTENT_MAX_BYTES) {
    session.current = null
    publish({ status: "failed", reason: "tooLarge" })
    return
  }
  publish({ status: "reading" })
  try {
    const text = await file.text()
    if (session.current !== token) return
    if (listContentTextTooLarge(text)) {
      publish({ status: "failed", reason: "tooLarge" })
      return
    }
    setText(text)
    publish({ status: "idle" })
  } catch {
    if (session.current === token)
      publish({ status: "failed", reason: "readFailed" })
  } finally {
    if (session.current === token) session.current = null
  }
}

export function appendListContentImport(
  current: { domains: string; ipCidrs: string },
  result: ListContentImportResponse
): { fields: typeof current; added: ListImportAdded } | null {
  if (!result.complete || result.errors.length) return null
  const append = (before: string, incoming: readonly string[]) => {
    const seen = new Set(
      before
        .split("\n")
        .map((value) => value.trim().toLowerCase())
        .filter(Boolean)
    )
    const additions = incoming.filter((value) => {
      const key = value.trim().toLowerCase()
      if (!key || seen.has(key)) return false
      seen.add(key)
      return true
    })
    return {
      value: additions.length
        ? before +
          (before && !before.endsWith("\n") ? "\n" : "") +
          additions.join("\n")
        : before,
      count: additions.length,
    }
  }
  const domains = append(current.domains, result.domains)
  const ipCidrs = append(current.ipCidrs, result.ip_cidrs)
  return {
    fields: { domains: domains.value, ipCidrs: ipCidrs.value },
    added: {
      domains: domains.count,
      ipCidrs: ipCidrs.count,
      duplicates:
        result.duplicates +
        result.domains.length +
        result.ip_cidrs.length -
        domains.count -
        ipCidrs.count,
    },
  }
}

export async function runListContentImport(
  session: ListImportSession,
  request: () => Promise<ListContentImportResponse>,
  add: (result: ListContentImportResponse) => ListImportAdded,
  publish: (state: ListContentImportState) => void
): Promise<void> {
  if (session.current) return
  const token = Symbol("list-import")
  session.current = token
  publish({ status: "pending" })
  try {
    const result = await request()
    if (session.current !== token) return
    if (!result.complete || result.errors.length) {
      publish({ status: "invalid", result })
      return
    }
    publish({ status: "added", added: add(result) })
  } catch {
    if (session.current === token)
      publish({ status: "failed", reason: "requestFailed" })
  } finally {
    if (session.current === token) session.current = null
  }
}

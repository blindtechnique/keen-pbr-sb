import type { CodeEditorSelection } from "@/components/shared/code-editor-selection"
import type { ServerFieldValidationError } from "@/lib/form-api-errors"

export function getListIpCidrEntryIndex(
  path: string,
  name: string
): number | null {
  const prefix = `lists.${name.trim()}.ip_cidrs`
  if (!name.trim() || !path.startsWith(prefix)) return null
  const match = /^\[(0|[1-9]\d*)\]$/.exec(path.slice(prefix.length))
  if (!match) return null
  const index = Number(match[1])
  return Number.isSafeInteger(index) ? index : null
}

export function isListIpCidrsPath(path: string, name: string): boolean {
  return (
    Boolean(name.trim()) &&
    (path === `lists.${name.trim()}.ip_cidrs` ||
      getListIpCidrEntryIndex(path, name) !== null)
  )
}

export function presentListIpCidrError(
  error: ServerFieldValidationError,
  name: string,
  submittedValue: string
): {
  error: ServerFieldValidationError
  selection: CodeEditorSelection | null
} {
  // Textarea normalizes CRLF. Otherwise this mirrors splitLines exactly:
  // comments and duplicates still occupy submitted indices. No IP parsing here.
  const value = submittedValue.replace(/\r\n/g, "\n")
  const positions: CodeEditorSelection[] = []
  let start = 0
  value.split("\n").forEach((text, index) => {
    if (text.trim())
      positions.push({
        value,
        line: index + 1,
        start,
        end: start + text.length,
      })
    start += text.length + 1
  })
  const lineNumbers: Record<string, number> = {}
  let selection: CodeEditorSelection | null = null
  for (const entry of error.entries) {
    const index = getListIpCidrEntryIndex(entry.path, name)
    const position = index === null ? undefined : positions[index]
    if (!position) continue
    lineNumbers[entry.path] = position.line
    selection ??= position
  }
  return { error: { ...error, lineNumbers }, selection }
}

/**
 * A WireGuard client profile is normally only a few kilobytes. Keep the
 * browser-side intake deliberately bounded before calling `File.text()` so a
 * dropped file can never turn this preview into an unbounded allocation.
 */
export const NATIVE_WIREGUARD_CONF_MAX_BYTES = 256 * 1024

export type NativeWireGuardImportFileIssue =
  | "single-file-only"
  | "conf-extension-required"
  | "empty-file"
  | "file-too-large"
  | "not-text"
  | "read-failed"

export type NativeWireGuardImportFileMetadata = Readonly<
  Pick<File, "name" | "size" | "type">
>

/** Prevents an older asynchronous `File.text()` from replacing newer UI. */
export function createNativeWireGuardFileReadGate() {
  let generation = 0
  return {
    begin(): number {
      generation += 1
      return generation
    },
    invalidate(): void {
      generation += 1
    },
    isCurrent(requestGeneration: number): boolean {
      return requestGeneration === generation
    },
  }
}

/**
 * The extension is intentional UX, not a security boundary. Browser MIME
 * detection for `.conf` is inconsistent (often empty), so the parser remains
 * the authority on content after this inexpensive pre-read guard.
 */
export function validateNativeWireGuardImportFile(
  file: NativeWireGuardImportFileMetadata
): NativeWireGuardImportFileIssue | undefined {
  if (!file.name.trim().toLowerCase().endsWith(".conf")) {
    return "conf-extension-required"
  }
  if (file.size <= 0) {
    return "empty-file"
  }
  if (file.size > NATIVE_WIREGUARD_CONF_MAX_BYTES) {
    return "file-too-large"
  }
  return undefined
}

/** Reject clearly binary/invalid decoding before schema parsing. */
export function validateNativeWireGuardImportText(
  text: string
): NativeWireGuardImportFileIssue | undefined {
  if (!text.trim()) {
    return "empty-file"
  }
  if (
    text.length > NATIVE_WIREGUARD_CONF_MAX_BYTES ||
    text.includes("\0") ||
    text.includes("\uFFFD")
  ) {
    return "not-text"
  }
  return undefined
}

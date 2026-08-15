/**
 * A WireGuard client profile is normally only a few kilobytes. Keep the
 * browser-side intake deliberately bounded before calling `File.text()` so a
 * dropped file can never turn this preview into an unbounded allocation.
 */
export const NATIVE_WIREGUARD_CONF_MAX_BYTES = 256 * 1024
export const NATIVE_WIREGUARD_URI_MAX_BYTES = 512 * 1024

export type NativeWireGuardImportFileIssue =
  | "single-file-only"
  | "supported-extension-required"
  | "empty-file"
  | "file-too-large"
  | "not-text"
  | "read-failed"

export type NativeWireGuardImportFileMetadata = Readonly<
  Pick<File, "name" | "size" | "type">
>

export type NativeWireGuardSensitiveInputKind = "vpn-uri" | "config"

/**
 * Keeps native secret-bearing material out of the ordinary sing-box link
 * state. URI schemes are case-insensitive, and malformed/partial WG configs
 * still need to be intercepted before their key text can reach a Save path.
 */
export function classifyNativeWireGuardSensitiveInput(
  text: string
): NativeWireGuardSensitiveInputKind | undefined {
  // A provider export may prefix the URI with a comment or a human label.
  // This field is link-only, so finding the native secret-bearing scheme
  // anywhere is sufficient reason to keep the whole value out of spec.link.
  if (/vpn:\/\//i.test(text)) return "vpn-uri"
  if (/^\s*\[(?:interface|peer)\]\s*(?:[#;].*)?$/im.test(text)) {
    return "config"
  }
  if (
    /^\s*(?:private[\s_-]*key|preshared[\s_-]*key)\s*(?:=|:)/im.test(text)
  ) {
    return "config"
  }
  return undefined
}

export function normalizeNativeWireGuardSensitiveInput(
  text: string,
  kind: NativeWireGuardSensitiveInputKind
): string {
  if (kind !== "vpn-uri") return text
  const match = /vpn:\/\//i.exec(text)
  return match
    ? `vpn://${text.slice(match.index + match[0].length).trim()}`
    : text
}

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
  const name = file.name.trim().toLowerCase()
  const isConf = name.endsWith(".conf")
  const isVpn = name.endsWith(".vpn")
  if (!isConf && !isVpn) {
    return "supported-extension-required"
  }
  if (file.size <= 0) {
    return "empty-file"
  }
  if (
    file.size >
    (isVpn ? NATIVE_WIREGUARD_URI_MAX_BYTES : NATIVE_WIREGUARD_CONF_MAX_BYTES)
  ) {
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
    new TextEncoder().encode(text).byteLength >
      (classifyNativeWireGuardSensitiveInput(text) === "vpn-uri"
        ? NATIVE_WIREGUARD_URI_MAX_BYTES
        : NATIVE_WIREGUARD_CONF_MAX_BYTES) ||
    text.includes("\0") ||
    text.includes("\uFFFD")
  ) {
    return "not-text"
  }
  return undefined
}

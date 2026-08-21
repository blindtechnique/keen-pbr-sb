import { NATIVE_WIREGUARD_CONF_MAX_BYTES } from "@/lib/native-wireguard-import-file"

export type NativeWireGuardImportKind = "wireguard" | "amnezia_wireguard"

export interface NativeWireGuardImportPreview {
  readonly kind: NativeWireGuardImportKind
  readonly address_count: number
  readonly dns_count: number
  readonly peer_count: number
  readonly allowed_ip_count: number
  readonly private_key_present: boolean
  readonly preshared_key_peer_count: number
  /** Host only; userinfo is never accepted and secret fields are never copied. */
  readonly endpoint_host?: string
  readonly endpoint_port?: number
  readonly persistent_keepalive?: number
  readonly listen_port?: number
  readonly mtu?: number
  /** Parameter names only, never values. */
  readonly amnezia_parameter_names: readonly string[]
}

export type NativeWireGuardImportErrorCode =
  | "input_too_large"
  | "invalid_encoding"
  | "unsupported_uri"
  | "invalid_base64"
  | "invalid_compression"
  | "invalid_json"
  | "unsupported_json_schema"
  | "malformed_line"
  | "unknown_section"
  | "duplicate_section"
  | "duplicate_field"
  | "duplicate_peer"
  | "unknown_field"
  | "dangerous_directive"
  | "missing_required_field"
  | "invalid_field"
  | "limit_exceeded"

export type NativeWireGuardImportPreviewResult =
  | { readonly ok: true; readonly preview: NativeWireGuardImportPreview }
  | {
      readonly ok: false
      readonly code: NativeWireGuardImportErrorCode
      /** Safe position only. Source text and key values are never returned. */
      readonly line?: number
    }

type ParsedSection = {
  readonly kind: "interface" | "peer"
  readonly fields: Map<string, string>
}

const INTERFACE_FIELDS = new Set([
  "privatekey",
  "address",
  "dns",
  "mtu",
  "listenport",
  "jc",
  "jmin",
  "jmax",
  "s1",
  "s2",
  "s3",
  "s4",
  "h1",
  "h2",
  "h3",
  "h4",
  "i1",
  "i2",
  "i3",
  "i4",
  "i5",
])
const PEER_FIELDS = new Set([
  "publickey",
  "presharedkey",
  "allowedips",
  "endpoint",
  "persistentkeepalive",
])
const AWG_FIELDS = new Set([
  "jc",
  "jmin",
  "jmax",
  "s1",
  "s2",
  "s3",
  "s4",
  "h1",
  "h2",
  "h3",
  "h4",
  "i1",
  "i2",
  "i3",
  "i4",
  "i5",
])
const DANGEROUS_FIELDS = new Set([
  "preup",
  "postup",
  "predown",
  "postdown",
  "table",
  "saveconfig",
])
const MAX_LINES = 4_096
const MAX_PEERS = 64
const MAX_LINE_BYTES = 8_192
const MAX_INTERFACE_ADDRESSES = 16
const MAX_DNS_SERVERS = 8
const MAX_ALLOWED_IPS_PER_PEER = 128
const MAX_TOTAL_ALLOWED_IPS = 512
const MAX_ENDPOINT_BYTES = 512
const MAX_AWG_HEADER_BYTES = 256
const MAX_AWG_SIGNATURE_BYTES = 4_096
const UINT32_MAX = 4_294_967_295
const CANONICAL_KEY_TAIL = "AEIMQUYcgkosw048"
const UTF8_ENCODER = new TextEncoder()

type ValidationResult<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly code: NativeWireGuardImportErrorCode }

/**
 * Browser-only, redacted preview of plain `.conf` files. The C++ importer is
 * authoritative for a future apply operation; this deliberately smaller
 * mirror never returns keys, raw lines or values outside the safe preview.
 */
export function parseNativeWireGuardConfigPreview(
  input: string
): NativeWireGuardImportPreviewResult {
  if (utf8Bytes(input) > NATIVE_WIREGUARD_CONF_MAX_BYTES) {
    return { ok: false, code: "input_too_large" }
  }
  if (hasInvalidBrowserTextEncoding(input)) {
    return { ok: false, code: "invalid_encoding" }
  }
  const leadingTrimLength = asciiTrimStartLength(input)
  const leadingLineOffset =
    input.slice(0, leadingTrimLength).split("\n").length - 1
  const trimmedInput = trimAscii(input)
  if (/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(trimmedInput)) {
    return { ok: false, code: "unsupported_uri" }
  }

  // C++ overwrites the three-byte UTF-8 BOM instead of shortening its input,
  // so keep the same byte length for the per-line limit.
  const normalizedInput = trimmedInput.startsWith("\uFEFF")
    ? `   ${trimmedInput.slice(1)}`
    : trimmedInput
  const lines = normalizedInput.split("\n")
  if (lines.length > MAX_LINES) {
    return { ok: false, code: "limit_exceeded" }
  }

  let interfaceSection: ParsedSection | undefined
  const peers: ParsedSection[] = []
  let current: ParsedSection | undefined

  for (const [index, rawLineWithCarriageReturn] of lines.entries()) {
    const lineNumber = leadingLineOffset + index + 1
    if (utf8Bytes(rawLineWithCarriageReturn) > MAX_LINE_BYTES) {
      return { ok: false, code: "limit_exceeded", line: lineNumber }
    }
    const rawLine = rawLineWithCarriageReturn.endsWith("\r")
      ? rawLineWithCarriageReturn.slice(0, -1)
      : rawLineWithCarriageReturn
    const line = stripInlineComment(rawLine)
    if (!line) continue

    if (line.startsWith("[") || line.endsWith("]")) {
      if (utf8Bytes(line) < 3 || !line.startsWith("[") || !line.endsWith("]")) {
        return { ok: false, code: "malformed_line", line: lineNumber }
      }
      const sectionName = asciiLower(trimAscii(line.slice(1, -1)))
      if (sectionName !== "interface" && sectionName !== "peer") {
        return { ok: false, code: "unknown_section", line: lineNumber }
      }

      if (sectionName === "interface") {
        if (interfaceSection) {
          return { ok: false, code: "duplicate_section", line: lineNumber }
        }
        if (peers.length > 0) {
          return { ok: false, code: "malformed_line", line: lineNumber }
        }
        current = { kind: "interface", fields: new Map() }
        interfaceSection = current
      } else {
        if (!interfaceSection) {
          return { ok: false, code: "malformed_line", line: lineNumber }
        }
        if (peers.length >= MAX_PEERS) {
          return { ok: false, code: "limit_exceeded", line: lineNumber }
        }
        current = { kind: "peer", fields: new Map() }
        peers.push(current)
      }
      continue
    }

    const separator = line.indexOf("=")
    if (!current || separator < 0) {
      return { ok: false, code: "malformed_line", line: lineNumber }
    }
    const rawName = trimAscii(line.slice(0, separator))
    if (!isValidFieldName(rawName)) {
      return { ok: false, code: "malformed_line", line: lineNumber }
    }
    const name = asciiLower(rawName)
    const value = trimAscii(line.slice(separator + 1))
    if (utf8Bytes(value) > MAX_LINE_BYTES) {
      return { ok: false, code: "limit_exceeded", line: lineNumber }
    }
    if (DANGEROUS_FIELDS.has(name)) {
      return { ok: false, code: "dangerous_directive", line: lineNumber }
    }
    const allowed =
      current.kind === "interface" ? INTERFACE_FIELDS : PEER_FIELDS
    if (!allowed.has(name)) {
      return { ok: false, code: "unknown_field", line: lineNumber }
    }
    if (current.fields.has(name)) {
      return { ok: false, code: "duplicate_field", line: lineNumber }
    }
    current.fields.set(name, value)
  }

  if (!interfaceSection) {
    return { ok: false, code: "missing_required_field" }
  }

  const address = requiredField(interfaceSection.fields, "address")
  if (address === undefined) {
    return { ok: false, code: "missing_required_field" }
  }
  const addresses = validateCidrList(address, MAX_INTERFACE_ADDRESSES)
  if (!addresses.ok) return addresses

  let dnsCount = 0
  if (interfaceSection.fields.has("dns")) {
    const dns = interfaceSection.fields.get("dns")!
    if (!dns) return { ok: false, code: "invalid_field" }
    const validatedDns = validateDnsList(dns)
    if (!validatedDns.ok) return validatedDns
    dnsCount = validatedDns.value
  }

  const listenPortValue = interfaceSection.fields.get("listenport")
  const mtuValue = interfaceSection.fields.get("mtu")
  const listenPort =
    listenPortValue === undefined
      ? undefined
      : parseInteger(listenPortValue, 0, 65_535)
  const parsedMtu =
    mtuValue === undefined ? undefined : parseInteger(mtuValue, 0, 65_535)
  const mtu = parsedMtu === 0 ? 1280 : parsedMtu
  if (
    (listenPortValue !== undefined && listenPort === undefined) ||
    (mtuValue !== undefined &&
      (mtu === undefined || (mtu !== 1280 && mtu < 576)))
  ) {
    return { ok: false, code: "invalid_field" }
  }

  const privateKey = requiredField(interfaceSection.fields, "privatekey")
  if (privateKey === undefined) {
    return { ok: false, code: "missing_required_field" }
  }
  if (!isWireGuardKey(privateKey)) {
    return { ok: false, code: "invalid_field" }
  }

  const awg = validateAmneziaFields(interfaceSection.fields)
  if (!awg.ok) return awg
  if (peers.length === 0) {
    return { ok: false, code: "missing_required_field" }
  }

  let allowedIpCount = 0
  let presharedKeyCount = 0
  const publicKeys = new Set<string>()
  let onlyEndpoint: { readonly host: string; readonly port: number } | undefined
  let onlyPersistentKeepalive: number | undefined
  for (const peer of peers) {
    const publicKey = requiredField(peer.fields, "publickey")
    if (publicKey === undefined) {
      return { ok: false, code: "missing_required_field" }
    }
    if (!isWireGuardKey(publicKey)) {
      return { ok: false, code: "invalid_field" }
    }
    if (publicKeys.has(publicKey)) {
      return { ok: false, code: "duplicate_peer" }
    }
    publicKeys.add(publicKey)

    const allowedIpsValue = requiredField(peer.fields, "allowedips")
    if (allowedIpsValue === undefined) {
      return { ok: false, code: "missing_required_field" }
    }
    const allowedIps = validateCidrList(
      allowedIpsValue,
      MAX_ALLOWED_IPS_PER_PEER
    )
    if (!allowedIps.ok) return allowedIps
    allowedIpCount += allowedIps.value
    if (allowedIpCount > MAX_TOTAL_ALLOWED_IPS) {
      return { ok: false, code: "limit_exceeded" }
    }

    const endpointValue = requiredField(peer.fields, "endpoint")
    if (endpointValue === undefined) {
      return { ok: false, code: "missing_required_field" }
    }
    const endpoint = parseEndpoint(endpointValue)
    if (!endpoint) return { ok: false, code: "invalid_field" }

    if (peer.fields.has("presharedkey")) {
      const presharedKey = requiredField(peer.fields, "presharedkey")
      if (presharedKey === undefined) {
        return { ok: false, code: "missing_required_field" }
      }
      if (!isWireGuardKey(presharedKey)) {
        return { ok: false, code: "invalid_field" }
      }
      presharedKeyCount += 1
    }

    let persistentKeepalive: number | undefined
    if (peer.fields.has("persistentkeepalive")) {
      persistentKeepalive = parseInteger(
        peer.fields.get("persistentkeepalive")!,
        0,
        65_535
      )
      if (persistentKeepalive === undefined) {
        return { ok: false, code: "invalid_field" }
      }
    }

    if (peers.length === 1) {
      onlyEndpoint = endpoint
      onlyPersistentKeepalive = persistentKeepalive
    }
  }

  return {
    ok: true,
    preview: {
      kind: awg.value ? "amnezia_wireguard" : "wireguard",
      address_count: addresses.value,
      dns_count: dnsCount,
      peer_count: peers.length,
      allowed_ip_count: allowedIpCount,
      private_key_present: true,
      preshared_key_peer_count: presharedKeyCount,
      ...(onlyEndpoint
        ? {
            endpoint_host: onlyEndpoint.host,
            endpoint_port: onlyEndpoint.port,
          }
        : {}),
      ...(onlyPersistentKeepalive !== undefined
        ? { persistent_keepalive: onlyPersistentKeepalive }
        : {}),
      ...(listenPort !== undefined ? { listen_port: listenPort } : {}),
      ...(mtu !== undefined ? { mtu } : {}),
      amnezia_parameter_names: awg.value ?? [],
    },
  }
}

function utf8Bytes(value: string): number {
  return UTF8_ENCODER.encode(value).byteLength
}

function hasInvalidBrowserTextEncoding(value: string): boolean {
  if (value.includes("\0") || value.includes("\uFFFD")) return true
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index)
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1)
      if (next < 0xdc00 || next > 0xdfff) return true
      index += 1
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true
    }
  }
  return false
}

function isAsciiWhitespace(character: string): boolean {
  const code = character.charCodeAt(0)
  return code === 0x20 || (code >= 0x09 && code <= 0x0d)
}

function trimAscii(value: string): string {
  const start = asciiTrimStartLength(value)
  let end = value.length
  while (end > start && isAsciiWhitespace(value[end - 1]!)) end -= 1
  return value.slice(start, end)
}

function asciiTrimStartLength(value: string): number {
  let start = 0
  while (start < value.length && isAsciiWhitespace(value[start]!)) start += 1
  return start
}

function asciiLower(value: string): string {
  return value.replace(/[A-Z]/g, (character) => character.toLowerCase())
}

function stripInlineComment(value: string): string {
  for (let index = 0; index < value.length; index += 1) {
    if (
      (value[index] === "#" || value[index] === ";") &&
      (index === 0 || isAsciiWhitespace(value[index - 1]!))
    ) {
      return trimAscii(value.slice(0, index))
    }
  }
  return trimAscii(value)
}

function isValidFieldName(value: string): boolean {
  return (
    value.length > 0 && utf8Bytes(value) <= 64 && /^[A-Za-z0-9_-]+$/.test(value)
  )
}

function requiredField(
  fields: ReadonlyMap<string, string>,
  name: string
): string | undefined {
  const value = fields.get(name)
  return value ? value : undefined
}

function validateCidrList(
  value: string,
  maximum: number
): ValidationResult<number> {
  let count = 0
  for (const rawItem of value.split(",")) {
    const item = trimAscii(rawItem)
    if (!item) return { ok: false, code: "invalid_field" }
    if (count >= maximum) return { ok: false, code: "limit_exceeded" }
    if (!isValidCidr(item)) return { ok: false, code: "invalid_field" }
    count += 1
  }
  return { ok: true, value: count }
}

function validateDnsList(value: string): ValidationResult<number> {
  let count = 0
  for (const rawItem of value.split(",")) {
    const item = trimAscii(rawItem)
    if (!item || !isValidIpAddress(item)) {
      return { ok: false, code: "invalid_field" }
    }
    if (count >= MAX_DNS_SERVERS) {
      return { ok: false, code: "limit_exceeded" }
    }
    count += 1
  }
  return { ok: true, value: count }
}

function parseInteger(
  value: string,
  minimum: number,
  maximum: number
): number | undefined {
  if (!/^\d+$/.test(value)) return undefined
  const parsed = Number(value)
  return Number.isSafeInteger(parsed) && parsed >= minimum && parsed <= maximum
    ? parsed
    : undefined
}

function parseEndpoint(
  value: string
): { readonly host: string; readonly port: number } | undefined {
  if (
    !value ||
    utf8Bytes(value) > MAX_ENDPOINT_BYTES ||
    [...value].some((character) => {
      const code = character.charCodeAt(0)
      return code < 0x20 || isAsciiWhitespace(character)
    })
  ) {
    return undefined
  }

  let host: string
  let portText: string
  if (value.startsWith("[")) {
    const close = value.indexOf("]")
    if (close < 0 || close + 1 >= value.length || value[close + 1] !== ":") {
      return undefined
    }
    host = value.slice(1, close)
    portText = value.slice(close + 2)
    if (!isValidIpv6(host)) return undefined
  } else {
    const colon = value.lastIndexOf(":")
    if (colon <= 0 || value.indexOf(":") !== colon) return undefined
    host = value.slice(0, colon)
    portText = value.slice(colon + 1)
    if (!isValidIpv4(host) && !isValidHostname(host)) return undefined
  }

  const port = parseInteger(portText, 1, 65_535)
  return port === undefined ? undefined : { host, port }
}

function isValidCidr(value: string): boolean {
  const slash = value.indexOf("/")
  const address = slash < 0 ? value : value.slice(0, slash)
  const version = isValidIpv4(address) ? 4 : isValidIpv6(address) ? 6 : 0
  if (version === 0) return false
  if (slash < 0) return true
  const prefix = value.slice(slash + 1)
  // addr_spec.hpp parses into a signed int; its only accepted negative-shaped
  // edge is `-0`, which converts to zero and survives the range check.
  if (!/^-?\d+$/.test(prefix)) return false
  const parsed = Number(prefix)
  return (
    Number.isSafeInteger(parsed) &&
    parsed >= 0 &&
    parsed <= (version === 4 ? 32 : 128)
  )
}

function isValidIpAddress(value: string): boolean {
  return isValidIpv4(value) || isValidIpv6(value)
}

function isValidIpv4(value: string): boolean {
  const parts = value.split(".")
  return (
    parts.length === 4 &&
    parts.every(
      (part) => /^(0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255
    )
  )
}

function isValidIpv6(value: string): boolean {
  if (!value.includes(":")) return false
  const compression = value.indexOf("::")
  if (compression !== value.lastIndexOf("::")) return false

  const hasCompression = compression >= 0
  const leftText = hasCompression ? value.slice(0, compression) : value
  const rightText = hasCompression ? value.slice(compression + 2) : ""
  const left = leftText ? leftText.split(":") : []
  const right = rightText ? rightText.split(":") : []
  const parts = [...left, ...right]
  if (parts.some((part) => !part)) return false

  let units = 0
  for (const [index, part] of parts.entries()) {
    if (part.includes(".")) {
      if (
        index !== parts.length - 1 ||
        !value.endsWith(part) ||
        !isValidIpv4(part)
      ) {
        return false
      }
      units += 2
    } else {
      if (!/^[0-9A-Fa-f]{1,4}$/.test(part)) return false
      units += 1
    }
  }
  return hasCompression ? units < 8 : units === 8
}

function isValidHostname(value: string): boolean {
  if (!value || utf8Bytes(value) > 253) return false
  const hostname = value.endsWith(".") ? value.slice(0, -1) : value
  if (!hostname) return false
  return hostname
    .split(".")
    .every(
      (label) =>
        label.length > 0 &&
        label.length <= 63 &&
        !label.startsWith("-") &&
        !label.endsWith("-") &&
        /^[A-Za-z0-9-]+$/.test(label)
    )
}

function validateAmneziaFields(
  fields: ReadonlyMap<string, string>
): ValidationResult<readonly string[] | undefined> {
  if (![...AWG_FIELDS].some((name) => fields.has(name))) {
    return { ok: true, value: undefined }
  }

  const numericNames = ["jc", "jmin", "jmax", "s1", "s2"] as const
  const numeric = new Map<string, number>()
  for (const name of numericNames) {
    const value = fields.get(name)
    if (value === undefined) {
      numeric.set(name, 0)
      continue
    }
    const parsed = parseInteger(value, 0, UINT32_MAX)
    if (parsed === undefined) return { ok: false, code: "invalid_field" }
    numeric.set(name, parsed)
  }

  const optionalNumeric = new Map<string, number>()
  for (const name of ["s3", "s4"] as const) {
    if (!fields.has(name)) continue
    const parsed = parseInteger(fields.get(name)!, 0, UINT32_MAX)
    if (parsed === undefined) return { ok: false, code: "invalid_field" }
    optionalNumeric.set(name, parsed)
  }

  const headers = new Map<string, string>()
  for (const name of ["h1", "h2", "h3", "h4"] as const) {
    const value = fields.get(name) ?? ""
    if (utf8Bytes(value) > MAX_AWG_HEADER_BYTES) {
      return { ok: false, code: "invalid_field" }
    }
    headers.set(name, value)
  }

  for (const name of ["i1", "i2", "i3", "i4", "i5"] as const) {
    const value = fields.get(name)
    if (value !== undefined && utf8Bytes(value) > MAX_AWG_SIGNATURE_BYTES) {
      return { ok: false, code: "invalid_field" }
    }
  }

  const names = ["Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"]
  if (optionalNumeric.has("s3") || optionalNumeric.has("s4")) {
    names.push("S3", "S4")
  }
  for (const name of ["I1", "I2", "I3", "I4", "I5"] as const) {
    if (fields.has(asciiLower(name))) names.push(name)
  }
  return { ok: true, value: names }
}

function isWireGuardKey(value: string): boolean {
  return (
    value.length === 44 &&
    /^[A-Za-z0-9+/]{42}$/.test(value.slice(0, 42)) &&
    CANONICAL_KEY_TAIL.includes(value[42]!) &&
    value[43] === "="
  )
}

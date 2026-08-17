import {
  NATIVE_WIREGUARD_CONF_MAX_BYTES,
  NATIVE_WIREGUARD_URI_MAX_BYTES,
} from "@/lib/native-wireguard-import-file"
import {
  parseNativeWireGuardConfigPreview,
  type NativeWireGuardImportErrorCode,
  type NativeWireGuardImportKind,
  type NativeWireGuardImportPreviewResult,
} from "@/lib/native-wireguard-config-preview"

type UriCandidate = {
  readonly expectedKind: NativeWireGuardImportKind
  readonly config: string
  readonly mtu?: number
  readonly listenPort?: number
}

type UriEnvelope = {
  readonly candidate: UriCandidate
  readonly primaryDns?: string
  readonly secondaryDns?: string
}

class PreviewFailure extends Error {
  readonly code: NativeWireGuardImportErrorCode

  constructor(code: NativeWireGuardImportErrorCode) {
    super(code)
    this.code = code
  }
}

/**
 * Parses either a plain WG/AWG config or the official Amnezia `vpn://`
 * qCompress envelope. The URI path accepts exactly one unambiguous WG/AWG
 * container and never returns the decoded JSON, config text or key material.
 */
export async function parseNativeWireGuardInputPreview(
  input: string
): Promise<NativeWireGuardImportPreviewResult> {
  if (
    new TextEncoder().encode(input).byteLength > NATIVE_WIREGUARD_URI_MAX_BYTES
  ) {
    return { ok: false, code: "input_too_large" }
  }
  const trimmed = trimAscii(input)
  if (!trimmed.startsWith("vpn://")) {
    return parseNativeWireGuardConfigPreview(input)
  }

  try {
    const compressed = decodeBase64Url(trimmed.slice(6))
    const decoded = await decompressQCompress(compressed)
    const envelope = parseEnvelope(decoded)
    const config = replacePlaceholder(
      replacePlaceholder(
        envelope.candidate.config,
        "$PRIMARY_DNS",
        envelope.primaryDns
      ),
      "$SECONDARY_DNS",
      envelope.secondaryDns
    )
    const result = parseNativeWireGuardConfigPreview(config)
    if (!result.ok) return result
    if (result.preview.kind !== envelope.candidate.expectedKind) {
      return { ok: false, code: "unsupported_json_schema" }
    }
    if (
      envelope.candidate.mtu !== undefined &&
      result.preview.mtu !== undefined &&
      result.preview.mtu !== envelope.candidate.mtu
    ) {
      return { ok: false, code: "unsupported_json_schema" }
    }
    if (
      envelope.candidate.listenPort !== undefined &&
      result.preview.listen_port !== undefined &&
      result.preview.listen_port !== envelope.candidate.listenPort
    ) {
      return { ok: false, code: "unsupported_json_schema" }
    }
    return {
      ok: true,
      preview: {
        ...result.preview,
        ...(result.preview.mtu === undefined &&
        envelope.candidate.mtu !== undefined
          ? { mtu: envelope.candidate.mtu }
          : {}),
        ...(result.preview.listen_port === undefined &&
        envelope.candidate.listenPort !== undefined
          ? { listen_port: envelope.candidate.listenPort }
          : {}),
      },
    }
  } catch (error) {
    return {
      ok: false,
      code: error instanceof PreviewFailure ? error.code : "invalid_json",
    }
  }
}

function decodeBase64Url(valueWithPadding: string): Uint8Array {
  let value = valueWithPadding
  let padding = 0
  while (value.endsWith("=")) {
    padding += 1
    value = value.slice(0, -1)
  }
  if (
    padding > 2 ||
    !value ||
    value.length % 4 === 1 ||
    (padding !== 0 && (value.length + padding) % 4 !== 0)
  ) {
    throw new PreviewFailure("invalid_base64")
  }

  const output = new Uint8Array(Math.floor((value.length * 6) / 8))
  let outputOffset = 0
  let accumulator = 0
  let bits = 0
  for (const character of value) {
    const decoded = base64UrlValue(character)
    if (decoded < 0) throw new PreviewFailure("invalid_base64")
    accumulator = (accumulator << 6) | decoded
    bits += 6
    if (bits >= 8) {
      bits -= 8
      output[outputOffset] = accumulator >> bits
      outputOffset += 1
      accumulator &= bits === 0 ? 0 : (1 << bits) - 1
    }
  }
  if (
    (bits !== 0 && accumulator !== 0) ||
    (padding === 1 && value.length % 4 !== 3) ||
    (padding === 2 && value.length % 4 !== 2)
  ) {
    throw new PreviewFailure("invalid_base64")
  }
  return output
}

function base64UrlValue(character: string): number {
  const code = character.charCodeAt(0)
  if (code >= 0x41 && code <= 0x5a) return code - 0x41
  if (code >= 0x61 && code <= 0x7a) return code - 0x61 + 26
  if (code >= 0x30 && code <= 0x39) return code - 0x30 + 52
  if (character === "-") return 62
  if (character === "_") return 63
  return -1
}

async function decompressQCompress(input: Uint8Array): Promise<string> {
  if (input.byteLength < 6) throw new PreviewFailure("invalid_compression")
  const expected =
    input[0]! * 0x1_00_00_00 +
    input[1]! * 0x1_00_00 +
    input[2]! * 0x1_00 +
    input[3]!
  if (expected === 0) throw new PreviewFailure("invalid_compression")
  if (expected > NATIVE_WIREGUARD_CONF_MAX_BYTES) {
    throw new PreviewFailure("limit_exceeded")
  }
  if (typeof DecompressionStream === "undefined") {
    throw new PreviewFailure("unsupported_uri")
  }

  try {
    const compressed = input.slice(4)
    const stream = new Blob([compressed.buffer])
      .stream()
      .pipeThrough(new DecompressionStream("deflate"))
    const reader = stream.getReader()
    const output = new Uint8Array(expected)
    let offset = 0
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      if (offset + value.byteLength > output.byteLength) {
        await reader.cancel()
        throw new PreviewFailure("invalid_compression")
      }
      output.set(value, offset)
      offset += value.byteLength
    }
    if (offset !== expected) {
      throw new PreviewFailure("invalid_compression")
    }
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(output)
    } catch {
      throw new PreviewFailure("invalid_json")
    }
  } catch (error) {
    if (error instanceof PreviewFailure) throw error
    throw new PreviewFailure("invalid_compression")
  }
}

function parseEnvelope(input: string): UriEnvelope {
  if (
    new TextEncoder().encode(input).byteLength > NATIVE_WIREGUARD_CONF_MAX_BYTES
  ) {
    throw new PreviewFailure("limit_exceeded")
  }
  const cursor = new JsonCursor(input)
  let candidate: UriCandidate | undefined
  let primaryDns: string | undefined
  let secondaryDns: string | undefined
  let sawContainers = false
  let sawDns1 = false
  let sawDns2 = false

  parseObject(cursor, (key, value) => {
    if (key === "containers") {
      if (sawContainers || value.peek() !== "[") unsupportedSchema()
      sawContainers = true
      parseArray(value, (_index, item) => {
        if (item.peek() !== "{") unsupportedSchema()
        const current = parseContainer(item)
        if (current) {
          if (candidate) unsupportedSchema()
          candidate = current
        }
      })
    } else if (key === "dns1" || key === "dns2") {
      if (value.peek() !== '"') unsupportedSchema()
      if (key === "dns1") {
        if (sawDns1) unsupportedSchema()
        primaryDns = value.readString()
        sawDns1 = true
      } else {
        if (sawDns2) unsupportedSchema()
        secondaryDns = value.readString()
        sawDns2 = true
      }
    } else {
      value.skipValue()
    }
  })
  cursor.finish()
  if (!sawContainers || !candidate) unsupportedSchema()
  return { candidate, primaryDns, secondaryDns }
}

function parseContainer(cursor: JsonCursor): UriCandidate | undefined {
  let candidate: UriCandidate | undefined
  parseObject(cursor, (key, value) => {
    const expectedKind =
      key === "awg"
        ? "amnezia_wireguard"
        : key === "wireguard"
          ? "wireguard"
          : undefined
    if (!expectedKind) {
      value.skipValue()
      return
    }
    if (candidate || value.peek() !== "{") unsupportedSchema()
    candidate = parseProtocolObject(value, expectedKind)
  })
  return candidate
}

function parseProtocolObject(
  cursor: JsonCursor,
  expectedKind: NativeWireGuardImportKind
): UriCandidate {
  let lastConfig: string | undefined
  parseObject(cursor, (key, value) => {
    if (key === "last_config") {
      if (lastConfig !== undefined || value.peek() !== '"') {
        unsupportedSchema()
      }
      lastConfig = value.readString()
    } else {
      value.skipValue()
    }
  })
  if (lastConfig === undefined) unsupportedSchema()
  return parseLastConfig(lastConfig, expectedKind)
}

function parseLastConfig(
  input: string,
  expectedKind: NativeWireGuardImportKind
): UriCandidate {
  if (
    new TextEncoder().encode(input).byteLength > NATIVE_WIREGUARD_CONF_MAX_BYTES
  ) {
    unsupportedSchema()
  }
  const cursor = new JsonCursor(input)
  let config: string | undefined
  let mtu: number | undefined
  let listenPort: number | undefined
  let sawMtu = false
  let sawPort = false
  parseObject(cursor, (key, value) => {
    if (key === "config") {
      if (config !== undefined || value.peek() !== '"') unsupportedSchema()
      config = value.readString()
    } else if (key === "mtu") {
      if (sawMtu) unsupportedSchema()
      mtu = readBoundedInteger(value, 576, 65_535)
      sawMtu = true
    } else if (key === "port") {
      if (sawPort) unsupportedSchema()
      listenPort = readBoundedInteger(value, 1, 65_535)
      sawPort = true
    } else {
      value.skipValue()
    }
  })
  cursor.finish()
  if (!config) unsupportedSchema()
  return { expectedKind, config, mtu, listenPort }
}

function readBoundedInteger(
  cursor: JsonCursor,
  minimum: number,
  maximum: number
): number {
  const text =
    cursor.peek() === '"' ? cursor.readString() : cursor.readNumberText()
  if (!/^\d+$/.test(text)) unsupportedSchema()
  const value = Number(text)
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    unsupportedSchema()
  }
  return value
}

function replacePlaceholder(
  input: string,
  placeholder: string,
  replacement: string | undefined
): string {
  if (!input.includes(placeholder)) return input
  if (!replacement) unsupportedSchema()
  const output = input.split(placeholder).join(replacement)
  if (
    new TextEncoder().encode(output).byteLength >
    NATIVE_WIREGUARD_CONF_MAX_BYTES
  ) {
    throw new PreviewFailure("limit_exceeded")
  }
  return output
}

function unsupportedSchema(): never {
  throw new PreviewFailure("unsupported_json_schema")
}

type JsonHandler = (key: string, cursor: JsonCursor) => void

function parseObject(cursor: JsonCursor, handler: JsonHandler): void {
  cursor.expect("{")
  if (cursor.consume("}")) return
  while (true) {
    const key = cursor.readString()
    cursor.expect(":")
    handler(key, cursor)
    if (cursor.consume("}")) return
    cursor.expect(",")
  }
}

function parseArray(
  cursor: JsonCursor,
  handler: (index: number, cursor: JsonCursor) => void
): void {
  cursor.expect("[")
  if (cursor.consume("]")) return
  let index = 0
  while (true) {
    handler(index, cursor)
    index += 1
    if (cursor.consume("]")) return
    cursor.expect(",")
  }
}

class JsonCursor {
  private offset = 0
  private readonly input: string

  constructor(input: string) {
    this.input = input
  }

  peek(): string {
    this.skipWhitespace()
    if (this.offset >= this.input.length) this.invalid()
    return this.input[this.offset]!
  }

  consume(expected: string): boolean {
    this.skipWhitespace()
    if (this.input[this.offset] === expected) {
      this.offset += 1
      return true
    }
    return false
  }

  expect(expected: string): void {
    if (!this.consume(expected)) this.invalid()
  }

  finish(): void {
    this.skipWhitespace()
    if (this.offset !== this.input.length) this.invalid()
  }

  readString(): string {
    return this.readStringInternal(true)
  }

  readNumberText(): string {
    this.skipWhitespace()
    const start = this.offset
    this.skipNumber()
    return this.input.slice(start, this.offset)
  }

  skipValue(depth = 0): void {
    if (depth > 32) this.invalid()
    const token = this.peek()
    if (token === '"') {
      this.readStringInternal(false)
    } else if (token === "{") {
      this.expect("{")
      if (this.consume("}")) return
      while (true) {
        this.readStringInternal(false)
        this.expect(":")
        this.skipValue(depth + 1)
        if (this.consume("}")) return
        this.expect(",")
      }
    } else if (token === "[") {
      this.expect("[")
      if (this.consume("]")) return
      while (true) {
        this.skipValue(depth + 1)
        if (this.consume("]")) return
        this.expect(",")
      }
    } else if (this.input.startsWith("true", this.offset)) {
      this.offset += 4
    } else if (this.input.startsWith("false", this.offset)) {
      this.offset += 5
    } else if (this.input.startsWith("null", this.offset)) {
      this.offset += 4
    } else {
      this.skipNumber()
    }
  }

  private readStringInternal(capture: boolean): string {
    this.skipWhitespace()
    if (this.input[this.offset] !== '"') this.invalid()
    this.offset += 1
    let output = ""
    while (this.offset < this.input.length) {
      const character = this.input[this.offset]!
      this.offset += 1
      if (character === '"') return output
      if (character.charCodeAt(0) < 0x20) this.invalid()
      if (character !== "\\") {
        if (capture) output += character
        continue
      }
      if (this.offset >= this.input.length) this.invalid()
      const escaped = this.input[this.offset]!
      this.offset += 1
      const simple: Readonly<Record<string, string>> = {
        '"': '"',
        "\\": "\\",
        "/": "/",
        b: "\b",
        f: "\f",
        n: "\n",
        r: "\r",
        t: "\t",
      }
      if (escaped in simple) {
        if (capture) output += simple[escaped]
        continue
      }
      if (escaped !== "u") this.invalid()
      let codepoint = this.readHexQuad()
      if (codepoint >= 0xd800 && codepoint <= 0xdbff) {
        if (this.input.slice(this.offset, this.offset + 2) !== "\\u") {
          this.invalid()
        }
        this.offset += 2
        const low = this.readHexQuad()
        if (low < 0xdc00 || low > 0xdfff) this.invalid()
        codepoint = 0x1_00_00 + ((codepoint - 0xd800) << 10) + (low - 0xdc00)
      } else if (codepoint >= 0xdc00 && codepoint <= 0xdfff) {
        this.invalid()
      }
      if (capture) output += String.fromCodePoint(codepoint)
    }
    this.invalid()
  }

  private readHexQuad(): number {
    const value = this.input.slice(this.offset, this.offset + 4)
    if (!/^[0-9A-Fa-f]{4}$/.test(value)) this.invalid()
    this.offset += 4
    return Number.parseInt(value, 16)
  }

  private skipNumber(): void {
    this.skipWhitespace()
    if (this.input[this.offset] === "-") this.offset += 1
    if (this.input[this.offset] === "0") {
      this.offset += 1
      if (/\d/.test(this.input[this.offset] ?? "")) this.invalid()
    } else {
      if (!/[1-9]/.test(this.input[this.offset] ?? "")) this.invalid()
      while (/\d/.test(this.input[this.offset] ?? "")) this.offset += 1
    }
    if (this.input[this.offset] === ".") {
      this.offset += 1
      if (!/\d/.test(this.input[this.offset] ?? "")) this.invalid()
      while (/\d/.test(this.input[this.offset] ?? "")) this.offset += 1
    }
    if (this.input[this.offset] === "e" || this.input[this.offset] === "E") {
      this.offset += 1
      if (this.input[this.offset] === "+" || this.input[this.offset] === "-") {
        this.offset += 1
      }
      if (!/\d/.test(this.input[this.offset] ?? "")) this.invalid()
      while (/\d/.test(this.input[this.offset] ?? "")) this.offset += 1
    }
  }

  private skipWhitespace(): void {
    while (this.offset < this.input.length) {
      const code = this.input.charCodeAt(this.offset)
      if (code !== 0x20 && code !== 0x09 && code !== 0x0a && code !== 0x0d) {
        break
      }
      this.offset += 1
    }
  }

  private invalid(): never {
    throw new PreviewFailure("invalid_json")
  }
}

function trimAscii(value: string): string {
  let start = 0
  let end = value.length
  while (start < end && isAsciiWhitespace(value[start]!)) start += 1
  while (end > start && isAsciiWhitespace(value[end - 1]!)) end -= 1
  return value.slice(start, end)
}

function isAsciiWhitespace(character: string): boolean {
  const code = character.charCodeAt(0)
  return code === 0x20 || (code >= 0x09 && code <= 0x0d)
}

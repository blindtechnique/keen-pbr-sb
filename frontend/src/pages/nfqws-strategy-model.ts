/**
 * A display-only view of the shell-style nfqws strategy file.
 *
 * This parser deliberately accepts a small, auditable subset of shell syntax.
 * It never evaluates input, and an unsupported construct degrades the summary
 * instead of guessing what the shell would do.
 */

export type NfqwsParseStatus = "complete" | "partial" | "incomplete"

export interface NfqwsRotation {
  readonly slots: number
  readonly fails?: number
  readonly timeSec?: number
  readonly retrans?: number
  readonly inseq?: number
  readonly stateKey?: string
}

export interface NfqwsPool {
  readonly id: string
  readonly name?: string
  readonly varName: string
  readonly transport: "tcp" | "udp" | "unknown"
  readonly tcpPorts?: string
  readonly udpPorts?: string
  readonly protocols: readonly string[]
  readonly domains: readonly string[]
  readonly rotation?: NfqwsRotation
  readonly techniques: readonly string[]
  /** The one shipped filter-only pool that is intentionally shown. */
  readonly filterOnly: boolean
}

export interface NfqwsStrategySummary {
  readonly pools: readonly NfqwsPool[]
  readonly blobCount: number
  readonly parseable: boolean
  readonly status: NfqwsParseStatus
}

const CANONICAL_VARS = new Set([
  "NFQWS_BASE_ARGS",
  "NFQWS_ARGS",
  "NFQWS_ARGS_QUIC",
  "NFQWS_ARGS_UDP",
  "NFQWS_ARGS_CUSTOM",
  "NFQWS_ARGS_IPSET",
])

const POOL_VARS = [
  "NFQWS_ARGS",
  "NFQWS_ARGS_QUIC",
  "NFQWS_ARGS_UDP",
  "NFQWS_ARGS_CUSTOM",
] as const

interface AssignmentScan {
  readonly values: ReadonlyMap<string, string>
  readonly unsupported: boolean
}

interface ParsedValue {
  readonly value: string
  readonly next: number
  readonly safe: boolean
}

function isHorizontalSpace(char: string | undefined): boolean {
  return char === " " || char === "\t"
}

function afterPhysicalLine(source: string, index: number): number {
  const newline = source.indexOf("\n", index)
  return newline === -1 ? source.length : newline + 1
}

function appendExpansion(
  source: string,
  index: number,
  environment: ReadonlyMap<string, string>
): { value: string; next: number; safe: boolean } {
  const first = source[index + 1]
  if (first && /[A-Za-z_]/.test(first)) {
    let end = index + 2
    while (end < source.length && /[A-Za-z0-9_]/.test(source[end] ?? "")) {
      end += 1
    }
    const name = source.slice(index + 1, end)
    const value = environment.get(name)
    return { value: value ?? "", next: end, safe: value !== undefined }
  }

  // Shell special parameters and all braced/arithmetic/command expansions are
  // outside the supported grammar. A plain dollar before punctuation is just
  // a literal dollar and is safe to display.
  if (
    first &&
    (/[0-9?#!@$*({"']/.test(first) || first === "-" || first === "[")
  ) {
    return { value: "", next: index + 2, safe: false }
  }
  return { value: "$", next: index + 1, safe: true }
}

function parseAssignmentValue(
  source: string,
  start: number,
  environment: ReadonlyMap<string, string>
): ParsedValue {
  let index = start
  let quote: "single" | "double" | undefined
  let value = ""
  let safe = true

  while (index < source.length) {
    const char = source[index]

    if (quote === "single") {
      if (char === "'") {
        quote = undefined
      } else {
        value += char
      }
      index += 1
      continue
    }

    if (quote === "double") {
      if (char === '"') {
        quote = undefined
        index += 1
        continue
      }
      if (char === "`") {
        safe = false
        index += 1
        continue
      }
      if (char === "$") {
        if (source[index + 1] === "'" || source[index + 1] === '"') {
          value += "$"
          index += 1
          continue
        }
        const expansion = appendExpansion(source, index, environment)
        value += expansion.value
        safe &&= expansion.safe
        index = expansion.next
        continue
      }
      if (char === "\\") {
        const escaped = source[index + 1]
        if (escaped === undefined) {
          safe = false
          index += 1
          continue
        }
        if (escaped === "\n") {
          index += 2
          continue
        }
        if (escaped === "\r" && source[index + 2] === "\n") {
          index += 3
          continue
        }
        if (
          escaped === '"' ||
          escaped === "\\" ||
          escaped === "$" ||
          escaped === "`"
        ) {
          value += escaped
        } else {
          // In double quotes, shell preserves a backslash before other bytes.
          value += `\\${escaped}`
        }
        index += 2
        continue
      }
      value += char
      index += 1
      continue
    }

    if (char === "\n" || (char === "\r" && source[index + 1] === "\n")) {
      return {
        value,
        next: index + (char === "\r" ? 2 : 1),
        safe,
      }
    }
    if (char === "'" || char === '"') {
      quote = char === "'" ? "single" : "double"
      index += 1
      continue
    }
    if (char === "`") {
      safe = false
      index += 1
      continue
    }
    if (char === "$") {
      const expansion = appendExpansion(source, index, environment)
      value += expansion.value
      safe &&= expansion.safe
      index = expansion.next
      continue
    }
    if (char === "\\") {
      const escaped = source[index + 1]
      if (escaped === undefined) {
        safe = false
        index += 1
        continue
      }
      if (escaped === "\n") {
        index += 2
        continue
      }
      if (escaped === "\r" && source[index + 2] === "\n") {
        index += 3
        continue
      }
      value += escaped
      index += 2
      continue
    }
    if (isHorizontalSpace(char)) {
      let tail = index
      while (isHorizontalSpace(source[tail])) tail += 1
      const tailChar = source[tail]
      if (
        tailChar === "#" ||
        tailChar === "\n" ||
        tailChar === "\r" ||
        tailChar === undefined
      ) {
        return {
          value,
          next: afterPhysicalLine(source, tail),
          safe,
        }
      }
      safe = false
      index = afterPhysicalLine(source, tail)
      return { value, next: index, safe }
    }
    if (/[;&|<>()]/.test(char)) {
      safe = false
    }
    if (char === "~") safe = false
    value += char
    index += 1
  }

  if (quote !== undefined) safe = false
  return { value, next: source.length, safe }
}

function scanShellAssignments(source: string): AssignmentScan {
  const environment = new Map<string, string>()
  const canonical = new Map<string, string>()
  let unsupported = false
  let index = 0

  while (index < source.length) {
    while (isHorizontalSpace(source[index])) index += 1
    const char = source[index]
    if (char === "\n") {
      index += 1
      continue
    }
    if (char === "\r" && source[index + 1] === "\n") {
      index += 2
      continue
    }
    if (char === "#") {
      index = afterPhysicalLine(source, index)
      continue
    }

    const nameMatch = /^[A-Za-z_][A-Za-z0-9_]*/.exec(source.slice(index))
    if (!nameMatch) {
      unsupported = true
      index = afterPhysicalLine(source, index)
      continue
    }
    const name = nameMatch[0]
    let cursor = index + name.length
    if (source[cursor] !== "=") {
      unsupported = true
      index = afterPhysicalLine(source, cursor)
      continue
    }
    cursor += 1

    const parsed = parseAssignmentValue(source, cursor, environment)
    index = parsed.next
    if (!parsed.safe) {
      unsupported = true
      environment.delete(name)
      canonical.delete(name)
      continue
    }

    environment.set(name, parsed.value)
    if (CANONICAL_VARS.has(name)) canonical.set(name, parsed.value)
  }

  return { values: canonical, unsupported }
}

/** Returns only safe assignments from the canonical nfqws strategy variables. */
export function parseShellAssignments(
  source: string
): ReadonlyMap<string, string> {
  return scanShellAssignments(source).values
}

interface Tokenization {
  readonly tokens: readonly string[]
  readonly complete: boolean
}

function tokenizeArgs(value: string): Tokenization {
  const tokens: string[] = []
  let token = ""
  let quote: "single" | "double" | undefined
  let index = 0

  const push = () => {
    if (token.length > 0) tokens.push(token)
    token = ""
  }

  while (index < value.length) {
    const char = value[index]
    if (quote) {
      if (
        (quote === "single" && char === "'") ||
        (quote === "double" && char === '"')
      ) {
        quote = undefined
        index += 1
        continue
      }
      if (char === "\\" && quote === "double") {
        const escaped = value[index + 1]
        if (escaped === undefined) return { tokens, complete: false }
        token += escaped
        index += 2
        continue
      }
      token += char
      index += 1
      continue
    }
    if (/\s/.test(char)) {
      push()
      index += 1
      continue
    }
    if (char === "'" || char === '"') {
      quote = char === "'" ? "single" : "double"
      index += 1
      continue
    }
    if (char === "\\") {
      const escaped = value[index + 1]
      if (escaped === undefined) return { tokens, complete: false }
      token += escaped
      index += 2
      continue
    }
    token += char
    index += 1
  }
  if (quote) return { tokens, complete: false }
  push()
  return { tokens, complete: true }
}

function extractOptionValue(
  tokens: readonly string[],
  option: string
): string | undefined {
  const prefix = `--${option}=`
  return tokens.find((token) => token.startsWith(prefix))?.slice(prefix.length)
}

function parseCircular(token: string): Omit<NfqwsRotation, "slots"> {
  const fields = new Map<string, string>()
  for (const part of token.split(":").slice(1)) {
    const equals = part.indexOf("=")
    if (equals > 0) fields.set(part.slice(0, equals), part.slice(equals + 1))
  }
  const number = (key: string) => {
    const raw = fields.get(key)
    if (raw === undefined) return undefined
    const parsed = Number(raw)
    return Number.isFinite(parsed) ? parsed : undefined
  }
  return {
    fails: number("fails"),
    timeSec: number("time"),
    retrans: number("retrans"),
    inseq: number("inseq"),
    stateKey: fields.get("key"),
  }
}

function splitCommaList(value: string | undefined): readonly string[] {
  return value
    ? value
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean)
    : []
}

function parsePool(
  varName: string,
  profileIndex: number,
  tokens: readonly string[],
  profileName: string | undefined,
  filterOnly: boolean
): NfqwsPool {
  const tcpPorts = extractOptionValue(tokens, "filter-tcp")
  const udpPorts = extractOptionValue(tokens, "filter-udp")
  const transport: NfqwsPool["transport"] =
    tcpPorts && !udpPorts ? "tcp" : udpPorts && !tcpPorts ? "udp" : "unknown"
  const strategyIds = new Set<string>()
  const techniques: string[] = []
  let actionCount = 0
  let rotationBase: Omit<NfqwsRotation, "slots"> | undefined

  for (const token of tokens) {
    if (!token.startsWith("--lua-desync=")) continue
    const body = token.slice("--lua-desync=".length)
    const method = body.split(":", 1)[0] ?? ""
    if (method === "circular") {
      rotationBase ??= parseCircular(body)
      continue
    }
    if (!method) continue
    actionCount += 1
    if (!techniques.includes(method)) techniques.push(method)
    const strategy = /(?:^|:)strategy=([^:]+)/.exec(body)?.[1]
    if (strategy) strategyIds.add(strategy)
  }

  const rotation = rotationBase
    ? {
        ...rotationBase,
        // Multiple techniques can belong to one strategy. If strategies are
        // not numbered at all, the only defensible display fallback is one.
        slots:
          strategyIds.size > 0 ? strategyIds.size : actionCount > 0 ? 1 : 0,
      }
    : undefined

  return {
    id: `${varName}#${profileIndex}`,
    name: profileName ?? rotation?.stateKey,
    varName,
    transport,
    tcpPorts,
    udpPorts,
    protocols: splitCommaList(extractOptionValue(tokens, "filter-l7")),
    domains: splitCommaList(extractOptionValue(tokens, "hostlist-domains")),
    rotation,
    techniques,
    filterOnly,
  }
}

interface Profile {
  readonly name?: string
  readonly tokens: readonly string[]
}

function customProfiles(tokens: readonly string[]): {
  profiles: readonly Profile[]
  complete: boolean
} {
  const profiles: Profile[] = []
  let current: string[] = []
  let currentName: string | undefined
  let complete = true

  const push = () => {
    if (current.length > 0)
      profiles.push({ name: currentName, tokens: current })
    current = []
  }

  for (const token of tokens) {
    if (token === "--new") {
      push()
      currentName = undefined
      continue
    }
    if (token.startsWith("--new=")) {
      push()
      const name = token.slice("--new=".length)
      if (/^[A-Za-z0-9_.-]+$/.test(name)) {
        currentName = name
      } else {
        currentName = undefined
        complete = false
      }
      continue
    }
    current.push(token)
  }
  push()
  return { profiles, complete }
}

function isApprovedWebrtcPassthrough(profile: Profile): boolean {
  if (profile.name !== "webrtc_passthrough" || profile.tokens.length !== 2) {
    return false
  }
  const exact = new Set(profile.tokens)
  return exact.has("--filter-udp=49152-65535") && exact.has("--filter-l7=stun")
}

export function parseNfqwsStrategy(content: string): NfqwsStrategySummary {
  const assignments = scanShellAssignments(content)
  const pools: NfqwsPool[] = []
  let unsupported = assignments.unsupported

  for (const varName of POOL_VARS) {
    const raw = assignments.values.get(varName)
    if (raw === undefined) continue
    const tokenization = tokenizeArgs(raw)
    unsupported ||= !tokenization.complete
    const split =
      varName === "NFQWS_ARGS_CUSTOM"
        ? customProfiles(tokenization.tokens)
        : { profiles: [{ tokens: tokenization.tokens }], complete: true }
    unsupported ||= !split.complete

    split.profiles.forEach((profile, profileIndex) => {
      const hasDesync = profile.tokens.some((token) =>
        token.startsWith("--lua-desync=")
      )
      const approvedPassthrough =
        varName === "NFQWS_ARGS_CUSTOM" && isApprovedWebrtcPassthrough(profile)
      if (!hasDesync && !approvedPassthrough) {
        if (profile.tokens.length > 0) unsupported = true
        return
      }
      pools.push(
        parsePool(
          varName,
          profileIndex,
          profile.tokens,
          profile.name,
          approvedPassthrough
        )
      )
    })
  }

  const base = tokenizeArgs(assignments.values.get("NFQWS_BASE_ARGS") ?? "")
  unsupported ||= !base.complete
  const blobCount = base.tokens.filter((token) =>
    token.startsWith("--blob=")
  ).length
  const parseable = pools.length > 0
  return {
    pools,
    blobCount,
    parseable,
    status: !parseable ? "incomplete" : unsupported ? "partial" : "complete",
  }
}

/** The three canonical profiles bundled by keen-pbr-sb. */
export type NfqwsProfileTier = "safe" | "balanced" | "max"

const PROFILE_MARKER = /^# keen-pbr-sb · профиль «([^»\r\n]+)»(?:\r?\n|$)/
const TIER_BY_ROLE: Readonly<Record<string, NfqwsProfileTier>> = {
  БЕЗОПАСНЫЙ: "safe",
  ОБЫЧНЫЙ: "balanced",
  МАКСИМАЛЬНЫЙ: "max",
}

export interface NfqwsProfileMarker {
  /** Undefined means the file has a profile marker with an unknown role. */
  readonly tier?: NfqwsProfileTier
  readonly role: string
}

/**
 * Reads only the generated first-line marker. Looking later in arbitrary shell
 * content would let a comment or string accidentally masquerade as a profile.
 */
export function parseNfqwsProfileMarker(
  content: string
): NfqwsProfileMarker | undefined {
  const match = PROFILE_MARKER.exec(content)
  if (!match) return undefined
  const role = match[1]!.trim()
  return { tier: TIER_BY_ROLE[role.toUpperCase()], role }
}

export interface NfqwsProfileCandidate {
  readonly builtin: boolean
  readonly overridden: boolean
  readonly canonical: boolean
  readonly content: string
}

/**
 * A marker alone is not authority to use the profile-card treatment: a custom
 * strategy carrying the same comment must stay in the table where its origin
 * and delete action remain visible.
 *
 * Applying a strategy creates an override, so `overridden` alone is not proof
 * of a user edit. The backend's `canonical` bit compares normalized strategy
 * identity with the current packaged profile (including rendered WAN and
 * owned telemetry differences). A copied marker therefore has no authority.
 */
export function canonicalNfqwsProfileTier(
  strategy: NfqwsProfileCandidate
): NfqwsProfileTier | undefined {
  if (!strategy.builtin || !strategy.canonical) return undefined
  return parseNfqwsProfileMarker(strategy.content)?.tier
}

export type NfqwsBuiltinStrategyDisplayKey =
  | "ver5Aggressive"
  | "ver7MoreAggressive"
  | "ver8MostAggressive"

const BUILTIN_STRATEGY_DISPLAY_KEYS: Readonly<
  Record<string, NfqwsBuiltinStrategyDisplayKey>
> = {
  "ver5 aggresive": "ver5Aggressive",
  "ver7 more aggresive": "ver7MoreAggressive",
  "ver8 max aggresive": "ver8MostAggressive",
}

/**
 * Corrects legacy spelling only for bundled entries. Their raw names remain
 * stable API identifiers; a custom strategy with the same name stays verbatim.
 */
export function nfqwsBuiltinStrategyDisplayKey(strategy: {
  readonly name: string
  readonly builtin: boolean
}): NfqwsBuiltinStrategyDisplayKey | undefined {
  if (!strategy.builtin) return undefined
  return BUILTIN_STRATEGY_DISPLAY_KEYS[strategy.name]
}

export const NFQWS_PROFILE_ORDER: readonly NfqwsProfileTier[] = [
  "safe",
  "balanced",
  "max",
]

export function nfqwsProtocolLabel(protocol: string): string {
  const labels: Record<string, string> = {
    tls: "TLS",
    http: "HTTP",
    quic: "QUIC",
    wireguard: "WireGuard",
    stun: "STUN",
    discord: "Discord",
    mtproto: "MTProto",
  }
  return labels[protocol.toLowerCase()] ?? protocol
}

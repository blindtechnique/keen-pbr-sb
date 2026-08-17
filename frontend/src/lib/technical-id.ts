export type TechnicalIdOptions = {
  maxLength?: number
  prefix?: string
}

export type RandomBytes = (length: number) => Uint8Array

export type GeneratedTechnicalIdOptions = {
  prefix: string
  existing?: Iterable<string>
  maxLength?: number
  randomBytes?: RandomBytes
}

export type TransportIdentityOptions = {
  existingInterfaces?: Iterable<string>
  existingTags?: Iterable<string>
  protocol?: string
}

const CYRILLIC_TRANSLITERATION: Readonly<Record<string, string>> = {
  а: "a",
  б: "b",
  в: "v",
  г: "g",
  д: "d",
  е: "e",
  ё: "e",
  ж: "zh",
  з: "z",
  и: "i",
  й: "y",
  к: "k",
  л: "l",
  м: "m",
  н: "n",
  о: "o",
  п: "p",
  р: "r",
  с: "s",
  т: "t",
  у: "u",
  ф: "f",
  х: "h",
  ц: "ts",
  ч: "ch",
  ш: "sh",
  щ: "sch",
  ъ: "",
  ы: "y",
  ь: "",
  э: "e",
  ю: "yu",
  я: "ya",
}

export function makeTechnicalId(
  label: string,
  existingIds: Iterable<string> = [],
  options: TechnicalIdOptions = {}
): string {
  const maxLength = Math.max(4, options.maxLength ?? 24)
  const prefix = normalizePrefix(options.prefix ?? "item", maxLength)
  const existing = new Set(existingIds)
  const base = normalizeTechnicalId(label, prefix, maxLength)

  if (!existing.has(base)) {
    return base
  }

  for (let sequence = 2; sequence < 10_000; sequence += 1) {
    const suffix = `_${sequence}`
    const candidate = `${base.slice(0, maxLength - suffix.length)}${suffix}`
    if (!existing.has(candidate)) {
      return candidate
    }
  }

  return base
}

export function normalizeTechnicalId(
  label: string,
  prefix = "item",
  maxLength = 24
): string {
  const transliterated = [...label.toLowerCase()]
    .map((character) => CYRILLIC_TRANSLITERATION[character] ?? character)
    .join("")
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
  const cleaned = transliterated
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
  const safePrefix = normalizePrefix(prefix, maxLength)
  const prefixed = /^[a-z]/.test(cleaned)
    ? cleaned
    : cleaned
      ? `${safePrefix}_${cleaned}`
      : safePrefix

  return prefixed.slice(0, maxLength).replace(/_+$/g, "") || safePrefix
}

export function generateTechnicalId({
  prefix,
  existing = [],
  maxLength = 24,
  randomBytes = secureRandomBytes,
}: GeneratedTechnicalIdOptions): string {
  const occupied = new Set(existing)
  const safePrefix = normalizeGeneratedPrefix(prefix, maxLength)

  for (let attempt = 0; attempt < 128; attempt += 1) {
    const token = bytesToHex(randomBytes(4))
    const candidate = `${safePrefix}${token}`.slice(0, maxLength)
    if (!occupied.has(candidate)) {
      return candidate
    }
  }

  return makeTechnicalId(safePrefix, occupied, {
    maxLength,
    prefix: safePrefix,
  })
}

export function generateTransportIdentity({
  existingInterfaces = [],
  existingTags = [],
  protocol,
}: TransportIdentityOptions = {}) {
  const interfaceNames = new Set(existingInterfaces)
  const tags = new Set(existingTags)
  const prefix = transportInterfacePrefix(protocol)

  for (let sequence = 1; sequence < 100_000; sequence += 1) {
    const interfaceName = `${prefix}${sequence}`.slice(0, 15)
    const tag = interfaceName
    if (!interfaceNames.has(interfaceName) && !tags.has(tag)) {
      return { interfaceName, tag }
    }
  }

  // This is practically unreachable, but keep a collision-safe fallback for a
  // deliberately hostile imported configuration.
  const tag = makeTechnicalId(`${prefix}_transport`, tags, {
    maxLength: 15,
    prefix,
  })
  return {
    interfaceName: makeTechnicalId(`${prefix}_interface`, interfaceNames, {
      maxLength: 15,
      prefix,
    }),
    tag,
  }
}

export function inferTransportProtocol(
  link: string | null | undefined,
  outboundJson: string | null | undefined
): string | undefined {
  const trimmedLink = link?.trim()
  if (trimmedLink) {
    const scheme = /^([a-z][a-z0-9+.-]*):\/\//i.exec(trimmedLink)?.[1]
    if (scheme) {
      return scheme
    }
  }

  const trimmedJson = outboundJson?.trim()
  if (!trimmedJson) {
    return undefined
  }

  try {
    const parsed = JSON.parse(trimmedJson) as unknown
    if (
      typeof parsed === "object" &&
      parsed !== null &&
      "type" in parsed &&
      typeof parsed.type === "string"
    ) {
      return parsed.type
    }
  } catch {
    return undefined
  }

  return undefined
}

function normalizePrefix(prefix: string, maxLength: number) {
  const cleaned = prefix
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
  const startsWithLetter = /^[a-z]/.test(cleaned) ? cleaned : `item_${cleaned}`

  return (startsWithLetter || "item").slice(0, maxLength).replace(/_+$/g, "")
}

function normalizeGeneratedPrefix(prefix: string, maxLength: number) {
  const cleaned = prefix.toLowerCase().replace(/[^a-z0-9_]+/g, "_")
  const startsWithLetter = /^[a-z]/.test(cleaned) ? cleaned : `item_${cleaned}`
  return (startsWithLetter || "item_").slice(0, Math.max(1, maxLength - 1))
}

function transportInterfacePrefix(protocol: string | undefined) {
  const normalized = protocol
    ?.trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "")

  switch (normalized) {
    case "vless":
      return "vless"
    case "vmess":
      return "vmess"
    case "hysteria":
    case "hysteria2":
    case "hy2":
      return "hys"
    case "shadowsocks":
    case "ss":
      return "ss"
    case "trojan":
      return "trojan"
    case "tuic":
      return "tuic"
    case "naive":
    case "naivehttps":
    case "naivequic":
      return "naive"
    case "wireguard":
    case "wg":
      return "wg"
    case "socks":
    case "socks5":
      return "socks"
    case "http":
    case "https":
      return "http"
    case "ssh":
      return "ssh"
    default:
      return "proxy"
  }
}

function secureRandomBytes(length: number) {
  const bytes = new Uint8Array(length)
  globalThis.crypto.getRandomValues(bytes)
  return bytes
}

function bytesToHex(bytes: Uint8Array) {
  return [...bytes].map((value) => value.toString(16).padStart(2, "0")).join("")
}

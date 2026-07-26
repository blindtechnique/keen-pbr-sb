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
  randomBytes?: RandomBytes
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
  randomBytes = secureRandomBytes,
}: TransportIdentityOptions = {}) {
  const interfaceNames = new Set(existingInterfaces)
  const tags = new Set(existingTags)

  for (let attempt = 0; attempt < 128; attempt += 1) {
    const token = bytesToHex(randomBytes(4))
    const interfaceName = `kpbr${token}`.slice(0, 15)
    const tag = `tr_${token}`.slice(0, 24)
    if (!interfaceNames.has(interfaceName) && !tags.has(tag)) {
      return { interfaceName, tag }
    }
  }

  const tag = makeTechnicalId("transport", tags, { prefix: "tr" })
  return {
    interfaceName: makeTechnicalId("kpbr", interfaceNames, {
      maxLength: 15,
      prefix: "kpbr",
    }),
    tag,
  }
}

function normalizePrefix(prefix: string, maxLength: number) {
  const cleaned = prefix
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
  const startsWithLetter = /^[a-z]/.test(cleaned)
    ? cleaned
    : `item_${cleaned}`

  return (startsWithLetter || "item").slice(0, maxLength).replace(/_+$/g, "")
}

function normalizeGeneratedPrefix(prefix: string, maxLength: number) {
  const cleaned = prefix.toLowerCase().replace(/[^a-z0-9_]+/g, "_")
  const startsWithLetter = /^[a-z]/.test(cleaned)
    ? cleaned
    : `item_${cleaned}`
  return (startsWithLetter || "item_").slice(0, Math.max(1, maxLength - 1))
}

function secureRandomBytes(length: number) {
  const bytes = new Uint8Array(length)
  globalThis.crypto.getRandomValues(bytes)
  return bytes
}

function bytesToHex(bytes: Uint8Array) {
  return [...bytes]
    .map((value) => value.toString(16).padStart(2, "0"))
    .join("")
}

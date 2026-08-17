type JsonComparable =
  | null
  | boolean
  | number
  | string
  | JsonComparable[]
  | { [key: string]: JsonComparable }

function normalizeJson(value: unknown): JsonComparable | undefined {
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "number" ||
    typeof value === "string"
  ) {
    return value
  }

  if (Array.isArray(value)) {
    return value.map((item) => normalizeJson(item) ?? null)
  }

  if (typeof value === "object") {
    const normalized: Record<string, JsonComparable> = {}

    for (const key of Object.keys(value).sort()) {
      const item = normalizeJson((value as Record<string, unknown>)[key])
      if (item !== undefined) {
        normalized[key] = item
      }
    }

    return normalized
  }

  return undefined
}

export function stableJsonStringify(value: unknown) {
  return JSON.stringify(normalizeJson(value))
}

export function semanticJsonEqual(left: unknown, right: unknown) {
  return stableJsonStringify(left) === stableJsonStringify(right)
}

import type { UpdateTransportOptions } from "@/api/generated/model"

export function parseUpdateTransport(value: unknown): UpdateTransportOptions {
  if (!value || typeof value !== "object")
    throw new Error("Invalid update transport response")
  const data = value as Record<string, unknown>
  if (
    typeof data.outbound !== "string" ||
    !Array.isArray(data.options) ||
    typeof data.options_available !== "boolean" ||
    (!data.options_available && data.options.length !== 0)
  )
    throw new Error("Invalid update transport response")
  const validTag = (tag: unknown): tag is string =>
    typeof tag === "string" && /^[a-z][a-z0-9_]{0,23}$/.test(tag)
  if (data.outbound !== "" && !validTag(data.outbound))
    throw new Error("Invalid update transport response")
  const seen = new Set<string>()
  const options = data.options.map((item: unknown) => {
    if (!item || typeof item !== "object")
      throw new Error("Invalid update transport response")
    const option = item as Record<string, unknown>
    if (
      !validTag(option.tag) ||
      typeof option.name !== "string" ||
      seen.has(option.tag)
    )
      throw new Error("Invalid update transport response")
    seen.add(option.tag)
    return { tag: option.tag, name: option.name || option.tag }
  })
  return {
    outbound: data.outbound,
    options,
    options_available: data.options_available,
  }
}

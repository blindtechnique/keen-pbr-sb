/** Wire properties unknown to this version must survive an ordinary form edit.
 * Known optional fields are deliberately excluded: clearing one in a form
 * must not restore its previous value when the payload omits it.
 */
export function pickUnknownConfigProperties(
  value: unknown,
  knownFields: readonly string[]
): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {}
  const known = new Set(knownFields)
  return Object.fromEntries(
    Object.entries(value).filter(([key]) => !known.has(key))
  )
}

export type ConfigUnknownFieldsDraft = {
  unknownFields?: Record<string, unknown>
}

export function toConfigUnknownFieldsDraft(
  value: unknown,
  knownFields: readonly string[]
): ConfigUnknownFieldsDraft {
  const unknownFields = pickUnknownConfigProperties(value, knownFields)
  return Object.keys(unknownFields).length ? { unknownFields } : {}
}

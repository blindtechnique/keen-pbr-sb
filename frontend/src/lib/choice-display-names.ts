/** UI-only labels: values remain the original stable IDs, never these captions. */
export function buildChoiceDisplayNames(
  choices: readonly { value: string; label: string }[]
): ReadonlyMap<string, string> {
  const labels = new Map(
    choices.map(({ value, label }) => [value, label.trim() || value])
  )
  const groups = new Map<string, string[]>()
  const normalize = (label: string) =>
    label.normalize("NFKC").toLocaleLowerCase("en-US")
  const reserved = new Set([...labels.values()].map(normalize))
  for (const [value, label] of labels) {
    const key = normalize(label)
    const values = groups.get(key) ?? []
    values.push(value)
    groups.set(key, values)
  }
  for (const values of groups.values()) {
    if (values.length < 2) continue
    // Stable within the full choice set, independent of rendering/filter order.
    values.sort((left, right) => (left < right ? -1 : left > right ? 1 : 0))
    let index = 1
    for (const value of values) {
      const label = labels.get(value)!
      let candidate: string
      do {
        candidate = `${label} · ${index++}`
      } while (reserved.has(normalize(candidate)))
      labels.set(value, candidate)
      reserved.add(normalize(candidate))
    }
  }
  return labels
}

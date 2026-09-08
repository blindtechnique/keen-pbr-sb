// Match ListParser::normalize_domain: DNS labels, optional '*.' and final dot.
// Order and repeated spellings have no effect on a suffix binding.
export function normalizeDnsDomainBindings(value: string): string[] | null {
  const domains = new Set<string>()
  for (const token of value.split(/[\s,;]+/).filter(Boolean)) {
    const domain = token.toLowerCase().replace(/^\*\./, "").replace(/\.$/, "")
    if (
      !domain ||
      domain.length > 253 ||
      !/[a-z]/.test(domain) ||
      !domain
        .split(".")
        .every(
          (label) =>
            label.length > 0 &&
            label.length <= 63 &&
            /^[a-z0-9_-]+$/.test(label) &&
            !label.startsWith("-") &&
            !label.endsWith("-")
        )
    ) {
      return null
    }
    domains.add(domain)
  }
  return [...domains].sort()
}

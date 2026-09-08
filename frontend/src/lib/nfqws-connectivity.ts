// This block lives in the existing exclude.list, alongside user entries.
// Its comments are also the checkbox state; no separate settings file is needed.
const BEGIN = "# keen-pbr: android-connectivity begin"
const END = "# keen-pbr: android-connectivity end"

export const ANDROID_CONNECTIVITY_DOMAINS = [
  "google.com",
  "connectivitycheck.gstatic.com",
  "connectivitycheck.android.com",
  "clients3.google.com",
  "clients4.google.com",
  "android.clients.google.com",
  "connect.rom.miui.com",
  "those.rom.miui.com",
  "status.rom.miui.com",
  "connectivitycheck.smartthings.com",
  "tpc.googlesyndication.com",
  "googleads.g.doubleclick.net",
] as const

function domainOf(line: string): string {
  // Match nfqws hostlist tokens: comments occupy a whole line or follow space.
  const token = line.trim().split(/\s/, 1)[0].toLowerCase()
  return /^[#;/]/.test(token) ? "" : token
}

function managedLines(source: string): {
  lines: string[]
  managed: Set<number>
} {
  const lines = source.match(/[^\n]*\n|[^\n]+$/g) ?? []
  const managed = new Set<number>()
  let start = -1
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index].trim()
    if (line === BEGIN) start = index
    if (line === END && start >= 0) {
      for (let member = start; member <= index; member += 1) managed.add(member)
      start = -1
    }
  }
  return { lines, managed }
}

export function androidConnectivityEnabled(source: string): boolean {
  const { lines, managed } = managedLines(source)
  const domains = new Set(lines.map(domainOf))
  return (
    managed.size > 0 &&
    ANDROID_CONNECTIVITY_DOMAINS.every((domain) => domains.has(domain))
  )
}

export function setAndroidConnectivityExclusions(
  source: string,
  enabled: boolean
): string {
  const { lines, managed } = managedLines(source)
  const ownedDomains = new Set<string>(ANDROID_CONNECTIVITY_DOMAINS)
  // Even inside our block, preserve unrelated lines inserted by the user.
  const userSource = lines
    .filter(
      (line, index) =>
        !managed.has(index) ||
        (line.trim() !== BEGIN &&
          line.trim() !== END &&
          !ownedDomains.has(domainOf(line)))
    )
    .join("")
  if (!enabled) return userSource

  const present = new Set(userSource.split("\n").map(domainOf))
  const additions = ANDROID_CONNECTIVITY_DOMAINS.filter(
    (domain) => !present.has(domain)
  )
  const newline = source.includes("\r\n") ? "\r\n" : "\n"
  const separator = userSource && !userSource.endsWith("\n") ? newline : ""
  return userSource + separator + [BEGIN, ...additions, END, ""].join(newline)
}

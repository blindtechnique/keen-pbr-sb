export type NativeWireGuardImportLocation = Readonly<{
  country: string
  country_code: string
}>

type GeoFetch = typeof fetch

type ResolveNativeWireGuardImportLocationOptions = Readonly<{
  fetchImpl?: GeoFetch
  attempts?: number
  intervalMs?: number
  sleep?: (milliseconds: number) => Promise<void>
}>

const wait = (milliseconds: number) =>
  new Promise<void>((resolve) => window.setTimeout(resolve, milliseconds))

/**
 * Resolve the endpoint the user already allowed auto-GeoIP for. Native
 * trackers intentionally contain no secret URI/server field, so persist this
 * small country snapshot after import instead of losing the flag forever.
 */
export async function resolveNativeWireGuardImportLocation(
  endpointHost: string,
  {
    fetchImpl = fetch,
    attempts = 6,
    intervalMs = 1_000,
    sleep = wait,
  }: ResolveNativeWireGuardImportLocationOptions = {}
): Promise<NativeWireGuardImportLocation | undefined> {
  const host = endpointHost.trim()
  if (!host || attempts < 1) return undefined

  for (let attempt = 0; attempt < attempts; attempt += 1) {
    let response: Response
    try {
      response = await fetchImpl("/api/system/geo", {
        method: "POST",
        credentials: "same-origin",
        cache: "no-store",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          hosts: [host],
          allow_external_lookup: true,
        }),
      })
    } catch {
      return undefined
    }
    if (!response.ok) return undefined

    const payload = (await response.json().catch(() => null)) as {
      locations?: Record<string, { country?: unknown; country_code?: unknown }>
      pending?: unknown
    } | null
    const location = payload?.locations?.[host]
    const country =
      typeof location?.country === "string" ? location.country.trim() : ""
    const countryCode =
      typeof location?.country_code === "string"
        ? location.country_code.trim().toUpperCase()
        : ""
    if (country && /^[A-Z]{2}$/.test(countryCode)) {
      return { country, country_code: countryCode }
    }
    if (payload?.pending !== true || attempt + 1 >= attempts) return undefined
    await sleep(intervalMs)
  }
  return undefined
}

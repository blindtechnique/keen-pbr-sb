import { useQuery } from "@tanstack/react-query"

import { resolveNativeWireGuardInterfaceLocation } from "@/lib/native-wireguard-import-geo"

export type ServerLocation = {
  country: string
  country_code?: string
  emoji?: string
}

/**
 * Где стоят серверы транспортов, по имени или адресу сервера.
 *
 * Определяет не роутер, а внешний сервис: собственной базы GeoIP у нас нет и
 * не будет — она весит на порядок больше всего остального пакета. Адрес
 * уходит наружу один раз и потом месяц берётся из кэша на диске.
 *
 * Ответ всегда необязательный: нет интернета, сервис недоступен, адрес не
 * разрешается — страна просто не показывается, и ничего больше не меняется.
 */
type LocationsResponse = {
  locations: Record<string, ServerLocation>
  pending: boolean
}

export function useServerLocations(
  hosts: string[],
  {
    allowExternalLookup,
  }: {
    allowExternalLookup: boolean
  }
) {
  const unique = Array.from(new Set(hosts.filter(Boolean))).sort()

  const query = useQuery<LocationsResponse>({
    queryKey: ["server-locations", unique, allowExternalLookup],
    enabled: unique.length > 0,
    queryFn: async () => {
      const response = await fetch("/api/system/geo", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          hosts: unique,
          allow_external_lookup: allowExternalLookup,
        }),
      })
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      const body = (await response.json()) as {
        locations?: Record<string, ServerLocation>
        pending?: boolean
      }
      return {
        locations: body.locations ?? {},
        pending: Boolean(body.pending),
      }
    },
    refetchInterval: (query) => (query.state.data?.pending ? 2_000 : false),
    staleTime: 30 * 24 * 60 * 60 * 1000,
    retry: false,
  })

  const locations = query.data?.locations ?? {}

  return {
    locations,
    locationOf: (host?: string) => (host ? locations[host] : undefined),
  }
}

export function useNativeInterfaceLocations(interfaces: string[]) {
  const unique = Array.from(
    new Set(interfaces.map((value) => value.trim()).filter(Boolean))
  ).sort()
  const query = useQuery<Record<string, ServerLocation>>({
    queryKey: ["native-interface-locations", unique],
    enabled: unique.length > 0,
    queryFn: async () => {
      const locations: Record<string, ServerLocation> = {}
      // The exit-check backend serializes probes. Keep this loop sequential so
      // several auto-labelled native tunnels do not turn each other into 409s.
      for (const device of unique) {
        const location = await resolveNativeWireGuardInterfaceLocation(device)
        if (location) locations[device] = location
      }
      return locations
    },
    staleTime: 30 * 24 * 60 * 60 * 1000,
    retry: false,
  })
  const locations = query.data ?? {}
  return {
    locations,
    locationOf: (device?: string) => (device ? locations[device] : undefined),
  }
}

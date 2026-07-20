import { useQuery } from "@tanstack/react-query"

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
export function useServerLocations(hosts: string[]) {
  const unique = Array.from(new Set(hosts.filter(Boolean))).sort()

  const query = useQuery<Record<string, ServerLocation>>({
    queryKey: ["server-locations", unique],
    enabled: unique.length > 0,
    queryFn: async () => {
      const response = await fetch("/api/system/geo", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ hosts: unique }),
      })
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      const body = (await response.json()) as {
        locations?: Record<string, ServerLocation>
      }
      return body.locations ?? {}
    },
    staleTime: 60 * 60 * 1000,
    retry: false,
  })

  const locations = query.data ?? {}

  return {
    locations,
    locationOf: (host?: string) => (host ? locations[host] : undefined),
  }
}

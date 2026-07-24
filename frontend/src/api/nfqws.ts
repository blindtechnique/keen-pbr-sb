import { queryOptions } from "@tanstack/react-query"

export type NfqwsActionResult = {
  ok: boolean
  output?: string
  strategy_created?: string
}

export type NfqwsUpdateStatus = {
  ok: boolean
  installed?: boolean
  current: string
  latest: string
  available: boolean
  release_url?: string
}

export const NFQWS_UPDATE_QUERY_KEY = ["nfqws", "update"] as const
export const NFQWS_UPDATE_INTERVAL_MS = 30 * 60 * 1_000

export async function nfqwsAction<T = NfqwsActionResult>(
  payload: Record<string, unknown>
): Promise<T> {
  const response = await fetch("/api/nfqws", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  })
  const data = await response.json().catch(() => ({}))
  if (!response.ok || data.ok === false) {
    throw new Error(
      data.error ??
        data.message ??
        data.output?.trim() ??
        `HTTP ${response.status}`
    )
  }
  return data as T
}

export function nfqwsUpdateQueryOptions() {
  return queryOptions({
    queryKey: NFQWS_UPDATE_QUERY_KEY,
    queryFn: () => nfqwsAction<NfqwsUpdateStatus>({ action: "check_update" }),
    retry: false,
    staleTime: NFQWS_UPDATE_INTERVAL_MS,
    refetchInterval: NFQWS_UPDATE_INTERVAL_MS,
    refetchIntervalInBackground: false,
    refetchOnWindowFocus: false,
  })
}

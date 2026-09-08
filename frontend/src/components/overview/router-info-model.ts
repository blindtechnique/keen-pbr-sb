import { queryOptions } from "@tanstack/react-query"

import type { RouterInfo, RouterMetrics } from "@/api/generated/model"

// The legacy router response also contains NDMS observations that older
// generated RouterInfo models did not declare.
export type RouterMetadata = RouterInfo & {
  available?: boolean
  internet?: boolean
  wan_address?: string
  clients_active?: number
  clients_total?: number
}

export type RouterInfoView = RouterMetadata &
  RouterMetrics & {
    available: boolean
  }

async function readRouterResponse<T>(path: string, signal: AbortSignal) {
  const response = await fetch(path, { signal })
  if (!response.ok) throw new Error(`HTTP ${response.status}`)
  return response.json() as Promise<T>
}

export function routerMetadataQueryOptions() {
  return queryOptions({
    queryKey: ["system-router"],
    queryFn: ({ signal }) =>
      readRouterResponse<RouterMetadata>("/api/system/router", signal),
    refetchInterval: 60_000,
    refetchIntervalInBackground: false,
  })
}

export function routerMetricsQueryOptions() {
  return queryOptions({
    queryKey: ["system-metrics"],
    queryFn: ({ signal }) =>
      readRouterResponse<RouterMetrics>("/api/system/metrics", signal),
    refetchInterval: 15_000,
    refetchIntervalInBackground: false,
  })
}

/** A late NDMS snapshot must never replace the independent local sample. */
export function routerInfoView(
  metadata: RouterMetadata | undefined,
  metrics: RouterMetrics | undefined
): RouterInfoView {
  const observed = metadata?.available === false ? undefined : metadata
  const info = {
    model: observed?.model,
    vendor: observed?.vendor,
    hw_id: observed?.hw_id,
    region: observed?.region,
    arch: observed?.arch,
    firmware_title: observed?.firmware_title,
    firmware_release: observed?.firmware_release,
    firmware_channel: observed?.firmware_channel,
    firmware_date: observed?.firmware_date,
    internet: observed?.internet,
    wan_address: observed?.wan_address,
    clients_active: observed?.clients_active,
    clients_total: observed?.clients_total,
    // Deliberately do not spread metadata: /system/router retains legacy local
    // fields for API compatibility, but they can be older than this sample.
    ...metrics,
  }
  return {
    ...info,
    available:
      metadata?.available === true ||
      Object.values(info).some(
        (value) =>
          value !== undefined &&
          value !== "" &&
          (!Array.isArray(value) || value.length > 0)
      ),
  }
}

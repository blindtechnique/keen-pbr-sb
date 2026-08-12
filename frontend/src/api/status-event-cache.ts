import { QueryClient } from "@tanstack/react-query"

import { noteRouterClock } from "@/api/router-clock"

import {
  getGetHealthServiceQueryKey,
  getGetRuntimeInterfacesQueryKey,
  getGetRuntimeOutboundsQueryKey,
  type getHealthServiceResponseSuccess,
  type getRuntimeInterfacesResponseSuccess,
  type getRuntimeOutboundsResponseSuccess,
} from "@/api/generated/keen-api"
import type {
  HealthResponse,
  RuntimeInterfaceInventoryEntry,
  RuntimeInterfaceInventoryResponse,
  RuntimeInterfaceTraffic,
  RuntimeInterfaceTrafficSample,
  RuntimeInterfaceTrafficUpdate,
  RuntimeOutboundsResponse,
  StatusEventInterfaces,
  StatusEventInterfaceTraffic,
  StatusEventConnections,
  StatusEventOutbounds,
  StatusEventService,
  StatusEventSnapshot,
} from "@/api/generated/model"

type StatusEvent =
  | StatusEventSnapshot
  | StatusEventService
  | StatusEventOutbounds
  | StatusEventInterfaces
  | StatusEventInterfaceTraffic
  | StatusEventConnections

const MAX_TRAFFIC_HISTORY_POINTS = 120
const DEFAULT_TRAFFIC_SAMPLE_INTERVAL_MS = 2_000
const MAX_TRAFFIC_SAMPLE_GAP_MS = 60_000

function response<T>(data: T) {
  return { data, status: 200 as const, headers: new Headers() }
}

export function applyStatusEvent(
  queryClient: QueryClient,
  rawData: string
): boolean {
  let event: StatusEvent
  try {
    event = JSON.parse(rawData) as StatusEvent
  } catch {
    return false
  }

  const setService = (data: HealthResponse) =>
    queryClient.setQueryData<getHealthServiceResponseSuccess>(
      getGetHealthServiceQueryKey(),
      response(data)
    )
  const setOutbounds = (data: RuntimeOutboundsResponse) =>
    queryClient.setQueryData<getRuntimeOutboundsResponseSuccess>(
      getGetRuntimeOutboundsQueryKey(),
      response(data)
    )
  const setInterfaces = (data: RuntimeInterfaceInventoryResponse) =>
    queryClient.setQueryData<getRuntimeInterfacesResponseSuccess>(
      getGetRuntimeInterfacesQueryKey(),
      response(data)
    )
  const mergeInterfaceTraffic = (data: RuntimeInterfaceTrafficUpdate) =>
    queryClient.setQueryData<getRuntimeInterfacesResponseSuccess>(
      getGetRuntimeInterfacesQueryKey(),
      (current) =>
        current
          ? response(
              applyInterfaceTrafficUpdate(current.data, data)
            )
          : current
    )

  switch (event?.type) {
    case "snapshot":
      setService(event.data.service)
      setOutbounds(event.data.outbounds)
      setInterfaces(event.data.interfaces)
      break
    case "service":
      setService(event.data)
      break
    case "outbounds":
      setOutbounds(event.data)
      break
    case "interfaces":
      setInterfaces(event.data)
      break
    case "interface_traffic":
      mergeInterfaceTraffic(event.data)
      break
    case "connections":
      void queryClient.invalidateQueries({ queryKey: ["connections"] })
      break
    default:
      return false
  }
  return true
}

export function applyInterfaceTrafficUpdate(
  inventory: RuntimeInterfaceInventoryResponse,
  update: RuntimeInterfaceTrafficUpdate
): RuntimeInterfaceInventoryResponse {
  // The batch stamp is the router's own "now" at send time, which makes it the
  // one value in this payload that can measure the offset between its clock
  // and ours. Everything that later asks "how old is this reading" needs that
  // offset, or it measures the disagreement between two machines instead.
  noteRouterClock(update.sampled_at_unix_ms)

  const samples = new Map(
    update.interfaces.map((sample) => [sample.name, sample])
  )

  return {
    ...inventory,
    interfaces: inventory.interfaces.map((entry) => {
      const sample = samples.get(entry.name)
      return sample
        ? mergeInterfaceTrafficEntry(entry, sample, update.sampled_at_unix_ms)
        : entry
    }),
  }
}

function mergeInterfaceTrafficEntry(
  entry: RuntimeInterfaceInventoryEntry,
  sample: RuntimeInterfaceTrafficSample,
  batchSampledAtUnixMs: number
): RuntimeInterfaceInventoryEntry {
  // When THIS interface was read, not when the round was dispatched. Stamping
  // every entry with the batch time made a stalled interface look exactly as
  // fresh as a live one, and dated the age of every history point by the
  // batch's elapsed time rather than its own. The batch value remains the
  // fallback for daemons that predate the per-interface field.
  const sampledAtUnixMs = sample.observed_at_unix_ms ?? batchSampledAtUnixMs
  if (!sample.available) {
    const withoutTraffic = { ...entry }
    delete withoutTraffic.traffic
    return withoutTraffic
  }
  if (sample.rx_bytes === undefined || sample.tx_bytes === undefined) {
    return entry
  }

  const previous = entry.traffic
  const elapsedMs = trafficSampleElapsedMs(
    previous?.sampled_at_unix_ms,
    sampledAtUnixMs
  )
  const history =
    sample.reset || !previous
      ? []
      : previous.history.map((point) => ({
          ...point,
          age_ms: point.age_ms + elapsedMs,
        }))
  history.push({
    age_ms: 0,
    rx_bits_per_second: sample.rx_bits_per_second ?? 0,
    tx_bits_per_second: sample.tx_bits_per_second ?? 0,
  })

  const traffic: RuntimeInterfaceTraffic = {
    sampled_at_unix_ms: sampledAtUnixMs,
    rx_bytes: sample.rx_bytes,
    tx_bytes: sample.tx_bytes,
    history: history.slice(-MAX_TRAFFIC_HISTORY_POINTS),
  }
  if (sample.rx_bits_per_second !== undefined) {
    traffic.rx_bits_per_second = sample.rx_bits_per_second
  }
  if (sample.tx_bits_per_second !== undefined) {
    traffic.tx_bits_per_second = sample.tx_bits_per_second
  }

  return { ...entry, traffic }
}

function trafficSampleElapsedMs(
  previousSampledAtUnixMs: number | undefined,
  sampledAtUnixMs: number
): number {
  if (
    previousSampledAtUnixMs === undefined ||
    sampledAtUnixMs <= previousSampledAtUnixMs
  ) {
    return DEFAULT_TRAFFIC_SAMPLE_INTERVAL_MS
  }
  return Math.min(
    sampledAtUnixMs - previousSampledAtUnixMs,
    MAX_TRAFFIC_SAMPLE_GAP_MS
  )
}

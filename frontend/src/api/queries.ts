import {
  getHealthService,
  getRuntimeInterfaces,
  getRuntimeOutbounds,
  useGetHealthService as useGeneratedHealthService,
  useGetRuntimeInterfaces as useGeneratedRuntimeInterfaces,
  useGetRuntimeOutbounds as useGeneratedRuntimeOutbounds,
} from "@/api/generated/keen-api"

export {
  getConfig,
  getDnsTest,
  getHealthRouting,
  getHealthService,
  getRuntimeInterfaces,
  getRuntimeOutbounds,
  getTransports,
  getTransportConfig,
  getGetConfigQueryOptions,
  getGetDnsTestQueryOptions,
  getGetHealthRoutingQueryOptions,
  getGetHealthServiceQueryOptions,
  getGetRuntimeInterfacesQueryOptions,
  getGetRuntimeOutboundsQueryOptions,
  getGetTransportsQueryOptions,
  getGetTransportConfigQueryOptions,
  useGetConfig,
  useGetDnsTest,
  useGetHealthRouting,
  useGetTransports,
  useGetTransportConfig,
} from "@/api/generated/keen-api"

export function useGetHealthService() {
  return useGeneratedHealthService<
    Awaited<ReturnType<typeof getHealthService>>
  >({
    // Fetch one baseline immediately. SSE remains the steady-state transport,
    // but a delayed or rejected stream must not leave the UI at "unknown".
    query: {
      refetchOnReconnect: false,
      refetchOnWindowFocus: false,
      staleTime: Number.POSITIVE_INFINITY,
    },
  })
}

export function useGetRuntimeOutbounds() {
  return useGeneratedRuntimeOutbounds<
    Awaited<ReturnType<typeof getRuntimeOutbounds>>
  >({
    query: {
      refetchOnReconnect: false,
      refetchOnWindowFocus: false,
      staleTime: Number.POSITIVE_INFINITY,
    },
  })
}

export function useGetRuntimeInterfaces() {
  return useGeneratedRuntimeInterfaces<
    Awaited<ReturnType<typeof getRuntimeInterfaces>>
  >({
    query: {
      refetchOnReconnect: false,
      refetchOnWindowFocus: false,
      staleTime: Number.POSITIVE_INFINITY,
    },
  })
}

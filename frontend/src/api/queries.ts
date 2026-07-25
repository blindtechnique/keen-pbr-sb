import {
  getNdmsInterfaceInventory,
  getHealthService,
  getRuntimeInterfaces,
  getRuntimeOutbounds,
  useGetNdmsInterfaceInventory as useGeneratedNdmsInterfaceInventory,
  useGetHealthService as useGeneratedHealthService,
  useGetRuntimeInterfaces as useGeneratedRuntimeInterfaces,
  useGetRuntimeOutbounds as useGeneratedRuntimeOutbounds,
} from "@/api/generated/keen-api"

export {
  getConfig,
  getDnsTest,
  getHealthRouting,
  getHealthService,
  getNdmsInterfaceInventory,
  getRuntimeInterfaces,
  getRuntimeOutbounds,
  getTransports,
  getTransportConfig,
  getGetConfigQueryOptions,
  getGetDnsTestQueryOptions,
  getGetHealthRoutingQueryOptions,
  getGetHealthServiceQueryOptions,
  getGetNdmsInterfaceInventoryQueryOptions,
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

export function useGetNdmsInterfaceInventory() {
  return useGeneratedNdmsInterfaceInventory<
    Awaited<ReturnType<typeof getNdmsInterfaceInventory>>
  >({
    query: {
      // NDMS metadata changes only when the firmware configuration changes.
      // Live link state comes from the shared runtime SSE snapshot instead of
      // adding another polling loop on a resource-constrained router.
      refetchOnReconnect: false,
      refetchOnWindowFocus: false,
      staleTime: Number.POSITIVE_INFINITY,
    },
  })
}

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

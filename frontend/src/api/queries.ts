import {
  getNdmsInterfaceInventory,
  getNdmsVpnServerServices,
  getHealthService,
  getRuntimeInterfaces,
  getRuntimeOutbounds,
  getTunnelProbeState,
  getRoutingRegistryConsent,
  useGetNdmsInterfaceInventory as useGeneratedNdmsInterfaceInventory,
  useGetNdmsVpnServerServices as useGeneratedNdmsVpnServerServices,
  useGetHealthService as useGeneratedHealthService,
  useGetRuntimeInterfaces as useGeneratedRuntimeInterfaces,
  useGetRuntimeOutbounds as useGeneratedRuntimeOutbounds,
  useGetRoutingRegistryConsent as useGeneratedRoutingRegistryConsent,
  useGetTunnelProbeState as useGeneratedTunnelProbeState,
} from "@/api/generated/keen-api"

export {
  getConfig,
  getDnsTest,
  getHealthRouting,
  getHealthService,
  getNdmsInterfaceInventory,
  getNdmsVpnServerServices,
  getRuntimeInterfaces,
  getRuntimeOutbounds,
  getRoutingRegistryConsent,
  getTransports,
  getTransportConfig,
  getGetConfigQueryOptions,
  getGetDnsTestQueryOptions,
  getGetHealthRoutingQueryOptions,
  getGetHealthServiceQueryOptions,
  getGetNdmsInterfaceInventoryQueryOptions,
  getGetNdmsVpnServerServicesQueryOptions,
  getGetRuntimeInterfacesQueryOptions,
  getGetRuntimeOutboundsQueryOptions,
  getGetRoutingRegistryConsentQueryOptions,
  getGetTransportsQueryOptions,
  getGetTransportConfigQueryOptions,
  useGetConfig,
  useGetDnsTest,
  useGetHealthRouting,
  useGetTransports,
  useGetTransportConfig,
} from "@/api/generated/keen-api"

export function useGetRoutingRegistryConsent() {
  return useGeneratedRoutingRegistryConsent<
    Awaited<ReturnType<typeof getRoutingRegistryConsent>>
  >({
    query: {
      // Consent changes only through the dedicated mutation. One baseline and
      // explicit invalidation avoid introducing another dashboard poller.
      refetchOnReconnect: false,
      refetchOnWindowFocus: false,
      staleTime: Number.POSITIVE_INFINITY,
    },
  })
}

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

export function useGetNdmsVpnServerServices() {
  return useGeneratedNdmsVpnServerServices<
    Awaited<ReturnType<typeof getNdmsVpnServerServices>>
  >({
    query: {
      // The service inventory is configuration metadata. A page visit obtains
      // one authoritative snapshot; steady-state traffic remains event driven.
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

// Опрашивается, а не кэшируется навсегда: проход автоматики случается сам по
// себе, раз в минуту, и смысл этих данных в том, что они свежие. Минута — тот
// же такт, с которым работает сама автоматика.
export function useGetTunnelProbeState() {
  return useGeneratedTunnelProbeState<
    Awaited<ReturnType<typeof getTunnelProbeState>>
  >({
    query: {
      refetchOnReconnect: false,
      refetchOnWindowFocus: false,
      refetchInterval: 60_000,
      staleTime: 30_000,
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

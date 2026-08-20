import {
  useIsMutating,
  useMutation,
  useQueryClient,
} from "@tanstack/react-query"

import {
  postListsRefresh,
  postListDeleteStage,
  postConfig,
  postConfigDiscard,
  postConfigSave,
  postRecommendedListSetup,
  postRoutingTest,
  postTransportAction,
  postTransportConfigApply,
  postTransportConfig,
  usePostListsRefresh,
  usePostListDeleteStage,
  usePostConfig,
  usePostConfigDiscard,
  usePostConfigSave,
  usePostRecommendedListSetup,
  usePostRoutingRegistryCheck,
  usePostRoutingRegistryConsent,
  usePostRoutingTest,
  usePostTransportAction,
  usePostTransportConfigApply,
  usePostTransportConfig,
  usePostSubscriptionPreview,
  usePostSubscriptionApply,
} from "@/api/generated/keen-api"
import {
  TransportConfigApplyRequestOperation,
  TransportLinkedOutboundEnsureMode,
  type TransportConfigApplyRequest,
  type TransportSpec,
} from "@/api/generated/model"
import {
  invalidationKeysAfterApplyConfigMutation,
  invalidationKeysAfterConfigMutation,
  invalidationKeysAfterListRefreshMutation,
  invalidationKeysAfterRuntimeActionMutation,
  queryKeys,
} from "@/api/query-keys"
import { apiFetch, type ApiError } from "@/api/client"

type UsePostListsRefreshOptions = Parameters<typeof usePostListsRefresh>[0]
type UsePostListDeleteStageOptions = Parameters<
  typeof usePostListDeleteStage<ApiError>
>[0]
type UsePostConfigOptions = Parameters<typeof usePostConfig>[0]
type UsePostConfigDiscardOptions = Parameters<typeof usePostConfigDiscard>[0]
type UsePostConfigSaveOptions = Parameters<typeof usePostConfigSave>[0]
type UsePostRecommendedListSetupOptions = Parameters<
  typeof usePostRecommendedListSetup
>[0]
type UsePostRoutingTestOptions = Parameters<typeof usePostRoutingTest>[0]
type UsePostRoutingRegistryCheckOptions = Parameters<
  typeof usePostRoutingRegistryCheck
>[0]
type UsePostRoutingRegistryConsentOptions = Parameters<
  typeof usePostRoutingRegistryConsent
>[0]
type UsePostTransportActionOptions = Parameters<
  typeof usePostTransportAction
>[0]
type UsePostTransportConfigOptions = Parameters<
  typeof usePostTransportConfig
>[0]
type UsePostSubscriptionPreviewOptions = Parameters<
  typeof usePostSubscriptionPreview
>[0]
type UsePostSubscriptionApplyOptions = Parameters<
  typeof usePostSubscriptionApply
>[0]

export function createLinkedTransportApplyRequest(
  transport: TransportSpec,
  strictEnforcement?: boolean
): TransportConfigApplyRequest {
  const displayName = transport.display_name?.trim()
  return {
    operation: TransportConfigApplyRequestOperation.create,
    transport,
    linked_outbound: {
      mode: TransportLinkedOutboundEnsureMode.ensure,
      display_name: displayName || undefined,
      // Undefined оставляет глобальную политику kill-switch — контракт
      // допускает null/omission именно с этим смыслом.
      strict_enforcement: strictEnforcement,
    },
  }
}

export const usePostTransportConfigApplyMutation = () => {
  const queryClient = useQueryClient()

  return usePostTransportConfigApply<ApiError>({
    mutation: {
      onSuccess: async () => {
        await Promise.all([
          queryClient.invalidateQueries({
            queryKey: queryKeys.transportConfig(),
          }),
          queryClient.invalidateQueries({
            queryKey: queryKeys.transports(),
          }),
          queryClient.invalidateQueries({
            queryKey: queryKeys.runtimeInterfaces(),
          }),
          queryClient.invalidateQueries({
            queryKey: queryKeys.runtimeOutbounds(),
          }),
          queryClient.invalidateQueries({
            queryKey: queryKeys.config(),
          }),
          queryClient.invalidateQueries({
            queryKey: queryKeys.healthService(),
          }),
          queryClient.invalidateQueries({
            queryKey: queryKeys.healthRouting(),
          }),
        ])
      },
    },
  })
}

export {
  postConfig,
  postConfigDiscard,
  postConfigSave,
  postListDeleteStage,
  postRecommendedListSetup,
  postListsRefresh,
  postRoutingTest,
  postTransportAction,
  postTransportConfigApply,
  postTransportConfig,
}

export const usePostListDeleteStageMutation = (
  options?: UsePostListDeleteStageOptions
) => {
  const queryClient = useQueryClient()

  return usePostListDeleteStage<ApiError>({
    ...options,
    mutation: {
      ...options?.mutation,
      onSuccess: async (data, variables, onMutateResult, context) => {
        for (const queryKey of invalidationKeysAfterConfigMutation) {
          await queryClient.invalidateQueries({ queryKey })
        }

        await options?.mutation?.onSuccess?.(
          data,
          variables,
          onMutateResult,
          context
        )
      },
    },
  })
}

export const usePostTransportConfigMutation = (
  options?: UsePostTransportConfigOptions
) => {
  const queryClient = useQueryClient()
  return usePostTransportConfig({
    ...options,
    mutation: {
      ...options?.mutation,
      onSuccess: async (data, variables, onMutateResult, context) => {
        await queryClient.invalidateQueries({
          queryKey: queryKeys.transportConfig(),
        })
        await queryClient.invalidateQueries({
          queryKey: queryKeys.transports(),
        })
        await queryClient.invalidateQueries({
          queryKey: queryKeys.runtimeInterfaces(),
        })
        await queryClient.invalidateQueries({
          queryKey: queryKeys.runtimeOutbounds(),
        })
        await options?.mutation?.onSuccess?.(
          data,
          variables,
          onMutateResult,
          context
        )
      },
    },
  })
}

// Preview is a read dressed as a POST: it fetches and plans but mutates
// nothing, so there is nothing to invalidate.
export const usePostSubscriptionPreviewMutation = (
  options?: UsePostSubscriptionPreviewOptions
) => {
  return usePostSubscriptionPreview(options)
}

export const usePostSubscriptionApplyMutation = (
  options?: UsePostSubscriptionApplyOptions
) => {
  const queryClient = useQueryClient()

  return usePostSubscriptionApply({
    ...options,
    mutation: {
      ...options?.mutation,
      onSuccess: async (data, variables, onMutateResult, context) => {
        // Same set as a manual transport create: apply reaches the same
        // manager pipeline, so the same views go stale.
        await queryClient.invalidateQueries({
          queryKey: queryKeys.transportConfig(),
        })
        await queryClient.invalidateQueries({
          queryKey: queryKeys.transports(),
        })
        await queryClient.invalidateQueries({
          queryKey: queryKeys.runtimeInterfaces(),
        })
        await queryClient.invalidateQueries({
          queryKey: queryKeys.runtimeOutbounds(),
        })
        await options?.mutation?.onSuccess?.(
          data,
          variables,
          onMutateResult,
          context
        )
      },
    },
  })
}

export const usePostTransportActionMutation = (
  options?: UsePostTransportActionOptions
) => {
  const queryClient = useQueryClient()

  return usePostTransportAction({
    ...options,
    mutation: {
      ...options?.mutation,
      onSuccess: async (data, variables, onMutateResult, context) => {
        await queryClient.invalidateQueries({
          queryKey: queryKeys.transports(),
        })
        await queryClient.invalidateQueries({
          queryKey: queryKeys.runtimeInterfaces(),
        })
        await queryClient.invalidateQueries({
          queryKey: queryKeys.runtimeOutbounds(),
        })
        await options?.mutation?.onSuccess?.(
          data,
          variables,
          onMutateResult,
          context
        )
      },
    },
  })
}

export const usePostListsRefreshMutation = (
  options?: UsePostListsRefreshOptions
) => {
  const queryClient = useQueryClient()

  return usePostListsRefresh({
    ...options,
    mutation: {
      ...options?.mutation,
      onSuccess: async (data, variables, onMutateResult, context) => {
        for (const queryKey of invalidationKeysAfterListRefreshMutation) {
          await queryClient.invalidateQueries({ queryKey })
        }

        await options?.mutation?.onSuccess?.(
          data,
          variables,
          onMutateResult,
          context
        )
      },
    },
  })
}

export const usePostConfigMutation = (options?: UsePostConfigOptions) => {
  const queryClient = useQueryClient()

  return usePostConfig({
    ...options,
    mutation: {
      ...options?.mutation,
      onSuccess: async (data, variables, onMutateResult, context) => {
        for (const queryKey of invalidationKeysAfterConfigMutation) {
          await queryClient.invalidateQueries({ queryKey })
        }

        await options?.mutation?.onSuccess?.(
          data,
          variables,
          onMutateResult,
          context
        )
      },
    },
  })
}

export const usePostRecommendedListSetupMutation = (
  options?: UsePostRecommendedListSetupOptions
) => {
  const queryClient = useQueryClient()

  return usePostRecommendedListSetup({
    ...options,
    mutation: {
      ...options?.mutation,
      onSuccess: async (data, variables, onMutateResult, context) => {
        for (const queryKey of invalidationKeysAfterConfigMutation) {
          await queryClient.invalidateQueries({ queryKey })
        }

        await options?.mutation?.onSuccess?.(
          data,
          variables,
          onMutateResult,
          context
        )
      },
    },
  })
}

export const useApplyConfigMutation = (options?: UsePostConfigSaveOptions) => {
  const queryClient = useQueryClient()

  return usePostConfigSave({
    ...options,
    mutation: {
      ...options?.mutation,
      onSuccess: async (data, variables, onMutateResult, context) => {
        for (const queryKey of invalidationKeysAfterApplyConfigMutation) {
          await queryClient.invalidateQueries({ queryKey })
        }

        await options?.mutation?.onSuccess?.(
          data,
          variables,
          onMutateResult,
          context
        )
      },
    },
  })
}

export const useDiscardConfigMutation = (
  options?: UsePostConfigDiscardOptions
) => {
  const queryClient = useQueryClient()

  return usePostConfigDiscard({
    ...options,
    mutation: {
      ...options?.mutation,
      onSuccess: async (data, variables, onMutateResult, context) => {
        for (const queryKey of invalidationKeysAfterConfigMutation) {
          await queryClient.invalidateQueries({ queryKey })
        }

        await options?.mutation?.onSuccess?.(
          data,
          variables,
          onMutateResult,
          context
        )
      },
    },
  })
}

export const usePostRoutingTestMutation = (
  options?: UsePostRoutingTestOptions
) => usePostRoutingTest(options)

// The one call that leaves the router on purpose. It is a separate mutation
// from the routing test so that nothing renders it by accident: the panel asks
// only when someone presses the button.
export const usePostRoutingRegistryCheckMutation = (
  options?: UsePostRoutingRegistryCheckOptions
) => usePostRoutingRegistryCheck(options)

export const usePostRoutingRegistryConsentMutation = (
  options?: UsePostRoutingRegistryConsentOptions
) => {
  const queryClient = useQueryClient()
  return usePostRoutingRegistryConsent({
    ...options,
    mutation: {
      ...options?.mutation,
      onSuccess: async (data, variables, onMutateResult, context) => {
        await queryClient.invalidateQueries({
          queryKey: queryKeys.routingRegistryConsent(),
        })
        await options?.mutation?.onSuccess?.(
          data,
          variables,
          onMutateResult,
          context
        )
      },
    },
  })
}

type ServiceAction = "start" | "stop" | "restart"
const serviceActionMutationKey = (action: ServiceAction) =>
  ["serviceAction", action] as const

const postServiceAction = (action: ServiceAction) =>
  apiFetch(`/api/service/${action}`, {
    method: "POST",
  })

export const usePostServiceActionMutation = (action: ServiceAction) => {
  const queryClient = useQueryClient()

  return useMutation({
    mutationKey: serviceActionMutationKey(action),
    mutationFn: () => postServiceAction(action),
    onSuccess: async () => {
      for (const queryKey of invalidationKeysAfterRuntimeActionMutation) {
        await queryClient.invalidateQueries({ queryKey })
      }
    },
  })
}

export function isConfigMutationPending(
  postConfigCount: number,
  postConfigSaveCount: number,
  listDeleteStageCount = 0,
  postTransportConfigCount = 0,
  postTransportConfigApplyCount = 0,
  postConfigDiscardCount = 0
) {
  return (
    postConfigCount > 0 ||
    postConfigSaveCount > 0 ||
    listDeleteStageCount > 0 ||
    postTransportConfigCount > 0 ||
    postTransportConfigApplyCount > 0 ||
    postConfigDiscardCount > 0
  )
}

export const useConfigMutationPending = () => {
  const postConfigCount = useIsMutating({ mutationKey: ["postConfig"] })
  const postConfigSaveCount = useIsMutating({ mutationKey: ["postConfigSave"] })
  const postConfigDiscardCount = useIsMutating({
    mutationKey: ["postConfigDiscard"],
  })
  const listDeleteStageCount = useIsMutating({
    mutationKey: ["postListDeleteStage"],
  })
  const postTransportConfigCount = useIsMutating({
    mutationKey: ["postTransportConfig"],
  })
  const postTransportConfigApplyCount = useIsMutating({
    mutationKey: ["postTransportConfigApply"],
  })

  return isConfigMutationPending(
    postConfigCount,
    postConfigSaveCount,
    listDeleteStageCount,
    postTransportConfigCount,
    postTransportConfigApplyCount,
    postConfigDiscardCount
  )
}

export const useRoutingControlPendingState = () => {
  const postConfigCount = useIsMutating({ mutationKey: ["postConfig"] })
  const listDeleteStageCount = useIsMutating({
    mutationKey: ["postListDeleteStage"],
  })
  const draftPostPending = postConfigCount > 0 || listDeleteStageCount > 0
  const applyPending = useIsMutating({ mutationKey: ["postConfigSave"] }) > 0
  const discardPending =
    useIsMutating({ mutationKey: ["postConfigDiscard"] }) > 0
  const configMutationPending =
    draftPostPending || applyPending || discardPending
  const startPending =
    useIsMutating({ mutationKey: serviceActionMutationKey("start") }) > 0
  const stopPending =
    useIsMutating({ mutationKey: serviceActionMutationKey("stop") }) > 0
  const restartPending =
    useIsMutating({ mutationKey: serviceActionMutationKey("restart") }) > 0

  return {
    applyPending,
    discardPending,
    draftPostPending,
    configMutationPending,
    startPending,
    stopPending,
    restartPending,
    anyPending:
      configMutationPending || startPending || stopPending || restartPending,
  }
}

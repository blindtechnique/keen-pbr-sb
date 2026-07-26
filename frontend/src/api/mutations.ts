import {
  useIsMutating,
  useMutation,
  useQueryClient,
} from "@tanstack/react-query"

import {
  postListsRefresh,
  postConfig,
  postConfigSave,
  postRoutingTest,
  postTransportAction,
  postTransportConfigApply,
  postTransportConfig,
  usePostListsRefresh,
  usePostConfig,
  usePostConfigSave,
  usePostRoutingTest,
  usePostTransportAction,
  usePostTransportConfigApply,
  usePostTransportConfig,
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
type UsePostConfigOptions = Parameters<typeof usePostConfig>[0]
type UsePostConfigSaveOptions = Parameters<typeof usePostConfigSave>[0]
type UsePostRoutingTestOptions = Parameters<typeof usePostRoutingTest>[0]
type UsePostTransportActionOptions = Parameters<
  typeof usePostTransportAction
>[0]
type UsePostTransportConfigOptions = Parameters<
  typeof usePostTransportConfig
>[0]

export function createLinkedTransportApplyRequest(
  transport: TransportSpec
): TransportConfigApplyRequest {
  const displayName = transport.display_name?.trim()
  return {
    operation: TransportConfigApplyRequestOperation.create,
    transport,
    linked_outbound: {
      mode: TransportLinkedOutboundEnsureMode.ensure,
      display_name: displayName || undefined,
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
  postConfigSave,
  postListsRefresh,
  postRoutingTest,
  postTransportAction,
  postTransportConfigApply,
  postTransportConfig,
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

export const usePostRoutingTestMutation = (
  options?: UsePostRoutingTestOptions
) => usePostRoutingTest(options)

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
  postConfigSaveCount: number
) {
  return postConfigCount > 0 || postConfigSaveCount > 0
}

export const useConfigMutationPending = () => {
  const postConfigCount = useIsMutating({ mutationKey: ["postConfig"] })
  const postConfigSaveCount = useIsMutating({ mutationKey: ["postConfigSave"] })

  return isConfigMutationPending(postConfigCount, postConfigSaveCount)
}

export const useRoutingControlPendingState = () => {
  const draftPostPending = useIsMutating({ mutationKey: ["postConfig"] }) > 0
  const applyPending = useIsMutating({ mutationKey: ["postConfigSave"] }) > 0
  const configMutationPending = draftPostPending || applyPending
  const startPending =
    useIsMutating({ mutationKey: serviceActionMutationKey("start") }) > 0
  const stopPending =
    useIsMutating({ mutationKey: serviceActionMutationKey("stop") }) > 0
  const restartPending =
    useIsMutating({ mutationKey: serviceActionMutationKey("restart") }) > 0

  return {
    applyPending,
    draftPostPending,
    configMutationPending,
    startPending,
    stopPending,
    restartPending,
    anyPending:
      configMutationPending || startPending || stopPending || restartPending,
  }
}

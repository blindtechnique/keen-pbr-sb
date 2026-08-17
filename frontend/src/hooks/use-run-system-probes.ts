import { useMutation, useQueryClient } from "@tanstack/react-query"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"

import { queryKeys } from "@/api/query-keys"

type ProbeRunResponse = { ok: boolean; scheduled: boolean; tag?: string }

/**
 * Shared frontend entry point for the probe.
 *
 * Called with a tag it measures that one outbound; called with nothing it runs
 * the daemon-wide coalesced round, which is what the page-level button wants.
 * Passing the tag is what makes a per-row button mean the row it sits on -
 * before this, every row triggered the whole round.
 */
export function useRunSystemProbes() {
  const queryClient = useQueryClient()
  const { t } = useTranslation()

  return useMutation({
    mutationKey: ["system-probes", "run"],
    onMutate: () => ({
      runtimeUpdatedAt:
        queryClient.getQueryState(queryKeys.runtimeOutbounds())
          ?.dataUpdatedAt ?? 0,
    }),
    mutationFn: async (tag?: string): Promise<ProbeRunResponse> => {
      const response = await fetch("/api/system/probes/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        // An empty body keeps the endpoint's original whole-round meaning.
        body: tag ? JSON.stringify({ tag }) : "",
      })
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      return response.json()
    },
    // probe_interfaces_now() reconciles the shared runtime-outbound snapshot.
    // Its SSE event updates the query cache as soon as the round completes.
    // If that stream is unavailable, retain one delayed GET as a recovery path
    // instead of leaving the displayed latency stale indefinitely.
    onSuccess: (_data, _variables, baseline) => {
      window.setTimeout(() => {
        const currentUpdatedAt =
          queryClient.getQueryState(queryKeys.runtimeOutbounds())
            ?.dataUpdatedAt ?? 0
        if (currentUpdatedAt <= baseline.runtimeUpdatedAt) {
          void queryClient.invalidateQueries({
            queryKey: queryKeys.runtimeOutbounds(),
          })
        }
      }, 3_000)
    },
    onError: () => toast.error(t("transports.latencyRefreshFailed")),
  })
}

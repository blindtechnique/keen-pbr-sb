import { useMutation, useQueryClient } from "@tanstack/react-query"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"

import { queryKeys } from "@/api/query-keys"

type ProbeRunResponse = { ok: boolean; scheduled: boolean }

/** Shared frontend entry point for the daemon-wide, coalesced probe round. */
export function useRunSystemProbes() {
  const queryClient = useQueryClient()
  const { t } = useTranslation()

  return useMutation({
    mutationKey: ["system-probes", "run"],
    mutationFn: async (): Promise<ProbeRunResponse> => {
      const response = await fetch("/api/system/probes/run", { method: "POST" })
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      return response.json()
    },
    onSuccess: () => {
      window.setTimeout(() => {
        void Promise.all([
          queryClient.invalidateQueries({ queryKey: ["system-probes"] }),
          queryClient.invalidateQueries({ queryKey: queryKeys.runtimeOutbounds() }),
        ])
      }, 2_000)
    },
    onError: () => toast.error(t("transports.latencyRefreshFailed")),
  })
}

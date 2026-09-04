import { useMutation, useQueryClient } from "@tanstack/react-query"
import { useEffect, useRef, useState } from "react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"

import { queryKeys } from "@/api/query-keys"
import {
  ManualProbeError,
  mergeManualProbeObservation,
  runManualInterfaceProbe,
  type InterfaceProbeEntry,
  type InterfaceProbesResponse,
} from "@/lib/manual-interface-probe"

type ProbeRunResponse = {
  ok: boolean
  scheduled: boolean
  tag?: string
  probe?: InterfaceProbeEntry
}

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
  const controllers = useRef(new Map<string, AbortController>())
  const mounted = useRef(true)
  const [pendingTags, setPendingTags] = useState<ReadonlySet<string>>(new Set())
  const [measurements, setMeasurements] = useState<
    ReadonlyMap<string, InterfaceProbeEntry>
  >(new Map())

  useEffect(() => {
    mounted.current = true
    const pending = controllers.current
    return () => {
      mounted.current = false
      for (const controller of pending.values()) controller.abort()
      pending.clear()
    }
  }, [])

  const mutation = useMutation({
    mutationKey: ["system-probes", "run"],
    onMutate: () => ({
      runtimeUpdatedAt:
        queryClient.getQueryState(queryKeys.runtimeOutbounds())
          ?.dataUpdatedAt ?? 0,
    }),
    mutationFn: async (tag?: string): Promise<ProbeRunResponse> => {
      if (tag) {
        const controller = new AbortController()
        controllers.current.get(tag)?.abort()
        controllers.current.set(tag, controller)
        setPendingTags(new Set(controllers.current.keys()))
        try {
          const result = await runManualInterfaceProbe(tag, {
            signal: controller.signal,
          })
          // A GET begun before this measurement must not overwrite it later.
          await queryClient.cancelQueries({ queryKey: ["system-probes"] })
          controller.signal.throwIfAborted()
          queryClient.setQueryData<InterfaceProbesResponse>(
            ["system-probes"],
            (current) => mergeManualProbeObservation(current, result, tag)
          )
          const probe = result.probes[tag]
          setMeasurements((current) => new Map(current).set(tag, probe))
          return { ok: true, scheduled: true, tag, probe }
        } finally {
          if (controllers.current.get(tag) === controller) {
            controllers.current.delete(tag)
            if (mounted.current) {
              setPendingTags(new Set(controllers.current.keys()))
            }
          }
        }
      }
      const response = await fetch("/api/system/probes/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        // An empty body keeps the endpoint's original whole-round meaning.
        body: "",
      })
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      const result = await response.json()
      if (result.scheduled !== true) {
        throw new ManualProbeError("not_scheduled")
      }
      return result
    },
    // probe_interfaces_now() reconciles the shared runtime-outbound snapshot.
    // Its SSE event updates the query cache as soon as the round completes.
    // If that stream is unavailable, retain one delayed GET as a recovery path
    // instead of leaving the displayed latency stale indefinitely.
    onSuccess: (data, tag, baseline) => {
      if (!mounted.current) return
      if (tag) {
        if (data.probe?.success !== true || data.probe.attributed !== true) {
          toast.error(t("transports.latencyMeasurementFailed"))
        }
        return
      }
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
    onError: (error) => {
      if (!mounted.current || error.name === "AbortError") return
      if (error instanceof ManualProbeError) {
        toast.error(
          error.reason === "not_scheduled"
            ? t("transports.latencyRefreshNotStarted")
            : t("transports.latencyRefreshTimedOut")
        )
      } else {
        toast.error(t("transports.latencyRefreshFailed"))
      }
    },
  })
  return { ...mutation, pendingTags, measurements }
}

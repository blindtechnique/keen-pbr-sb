import type { InterfaceLatencyProbe } from "@/components/transports/transport-latency-model"

export type InterfaceProbeEntry = InterfaceLatencyProbe & {
  observation_id?: string
  error?: string
}

export type InterfaceProbesResponse = {
  interval_seconds: number
  probes: Record<string, InterfaceProbeEntry>
}

export class ManualProbeError extends Error {
  readonly reason: "not_scheduled" | "timeout"

  constructor(reason: "not_scheduled" | "timeout") {
    super(reason)
    this.reason = reason
  }
}

export function mergeManualProbeObservation(
  current: InterfaceProbesResponse | undefined,
  observed: InterfaceProbesResponse,
  tag: string
): InterfaceProbesResponse {
  const baseline = current ?? observed
  return {
    ...baseline,
    probes: { ...baseline.probes, [tag]: observed.probes[tag] },
  }
}

type ManualProbeOptions = {
  signal: AbortSignal
  fetch?: typeof fetch
  now?: () => number
  sleep?: (milliseconds: number, signal: AbortSignal) => Promise<void>
  timeoutMs?: number
}

function abortableSleep(milliseconds: number, signal: AbortSignal) {
  return new Promise<void>((resolve, reject) => {
    signal.throwIfAborted()
    const onAbort = () => {
      clearTimeout(timer)
      reject(signal.reason)
    }
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", onAbort)
      resolve()
    }, milliseconds)
    signal.addEventListener("abort", onAbort, { once: true })
  })
}

export async function readInterfaceProbes(
  signal?: AbortSignal,
  fetchImpl: typeof fetch = fetch
): Promise<InterfaceProbesResponse> {
  const response = await fetchImpl("/api/system/probes", {
    signal,
    cache: "no-store",
  })
  if (!response.ok) throw new Error(`HTTP ${response.status}`)
  return response.json()
}

/** Wait only for a new real observation of the requested row, never another
 * row's SSE update. This polling exists only for the duration of one click. */
export async function runManualInterfaceProbe(
  tag: string,
  options: ManualProbeOptions
): Promise<InterfaceProbesResponse> {
  const fetchImpl = options.fetch ?? fetch
  const now = options.now ?? Date.now
  const sleep = options.sleep ?? abortableSleep
  const timeoutMs = options.timeoutMs ?? 20_000
  const controller = new AbortController()
  const forwardAbort = () => controller.abort(options.signal.reason)
  options.signal.throwIfAborted()
  options.signal.addEventListener("abort", forwardAbort, { once: true })
  const deadline = now() + timeoutMs
  const timer = setTimeout(
    () => controller.abort(new ManualProbeError("timeout")),
    timeoutMs
  )
  try {
    const before = await readInterfaceProbes(controller.signal, fetchImpl)
    const baseline = before.probes[tag]
    controller.signal.throwIfAborted()
    const response = await fetchImpl("/api/system/probes/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tag }),
      signal: controller.signal,
    })
    if (!response.ok) throw new Error(`HTTP ${response.status}`)
    const admission = await response.json()
    if (admission.scheduled !== true) {
      throw new ManualProbeError("not_scheduled")
    }
    for (;;) {
      controller.signal.throwIfAborted()
      const current = await readInterfaceProbes(controller.signal, fetchImpl)
      controller.signal.throwIfAborted()
      const observation = current.probes[tag]
      if (
        observation?.observation_id &&
        observation.observation_id !== baseline?.observation_id &&
        (!baseline?.interface || observation.interface === baseline.interface)
      ) {
        return current
      }
      if (now() >= deadline) throw new ManualProbeError("timeout")
      await sleep(Math.min(400, deadline - now()), controller.signal)
    }
  } catch (error) {
    if (controller.signal.aborted) throw controller.signal.reason
    throw error
  } finally {
    clearTimeout(timer)
    options.signal.removeEventListener("abort", forwardAbort)
  }
}

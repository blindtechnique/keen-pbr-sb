import {
  waitForRuntimeReadiness,
  type RuntimeReadinessHealth,
  type RuntimeReadinessProbe,
} from "@/lib/runtime-readiness"

type ProcessRestartProbe = Omit<
  RuntimeReadinessProbe,
  "health" | "transports"
> & {
  health: () => Promise<RuntimeReadinessHealth & { daemon_pid?: number }>
  transports: NonNullable<RuntimeReadinessProbe["transports"]>
}

type Options = {
  expectedTransportTags?: readonly string[]
  timeoutMs?: number
  intervalMs?: number
  now?: () => number
  sleep?: (duration: number) => Promise<void>
}

/** A healthy response from the retiring daemon is not a completed restart. */
export async function waitForServiceProcessRestart(
  probe: ProcessRestartProbe,
  previousPid: number | undefined,
  options: Options = {}
): Promise<void> {
  const now = options.now ?? Date.now
  const sleep =
    options.sleep ??
    ((duration) =>
      new Promise<void>((resolve) => globalThis.setTimeout(resolve, duration)))
  const deadline = now() + (options.timeoutMs ?? 120_000)
  const intervalMs = options.intervalMs ?? 1_000
  do {
    try {
      const health = await probe.health()
      if (
        previousPid !== undefined &&
        health.daemon_pid &&
        health.daemon_pid !== previousPid
      ) {
        // Even with no configured VPNs, require the companion API to return.
        await probe.transports()
        await waitForRuntimeReadiness(probe, {
          expectedTransportTags: options.expectedTransportTags,
          timeoutMs: Math.max(0, deadline - now()),
          intervalMs,
          sleep,
        })
        return
      }
    } catch {
      // A short disconnect is expected while the two processes are replaced.
    }
    if (now() >= deadline) break
    await sleep(intervalMs)
  } while (now() < deadline)
  throw new Error("service_process_restart_timeout")
}

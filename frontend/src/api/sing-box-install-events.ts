// Progress for the sing-box install.
//
// The install runs inside one HTTP request that takes a minute or more and
// replaces the binary every sing-box transport runs on. Without this the page
// showed a spinner: an operator could not tell a slow download from a hung
// one, a second tab could not tell that anything was happening, and a page
// reloaded mid-install offered a button to start another.
//
// Deliberately not carried on `component_transaction`, which has the same
// payload shape. That event lands in a single unfiltered slot
// (component-transaction-events.ts) rendered by the nfqws panel with no check
// on which component it names, so sharing it would draw sing-box steps on a
// page about a different program.

export type SingBoxInstallProgress = {
  // A phase name from the daemon's installer, or "finished".
  phase: string
  active: boolean
  pinnedVersion: string
  // Only meaningful when the install has ended. Either an install outcome name
  // or "aborted" when the request died before it could report one.
  outcome: string
}

type Listener = (progress: SingBoxInstallProgress | null) => void

const listeners = new Set<Listener>()
let current: SingBoxInstallProgress | null = null

export function subscribeSingBoxInstall(listener: Listener) {
  listeners.add(listener)
  // The stream replays its last frame to a new subscriber, but a component
  // already mounted when that frame arrived would otherwise never see it.
  listener(current)
  return () => {
    listeners.delete(listener)
  }
}

export function getSingBoxInstallProgress() {
  return current
}

export function applySingBoxInstallStatusEvent(serialized: string): boolean {
  const parsed = parse(serialized)
  if (!parsed) return false
  // A finished install stops being progress rather than becoming progress
  // that says "finished" forever. The result of the install is reported by
  // the response to the request that asked for it; this stream answers only
  // "is one running, and where is it".
  current = parsed.active ? parsed : null
  for (const listener of listeners) listener(current)
  return true
}

// Exported for tests: a page must not have to fake an EventSource to prove it
// handles a malformed frame.
export function resetSingBoxInstallProgress() {
  current = null
  for (const listener of listeners) listener(current)
}

function parse(serialized: string): SingBoxInstallProgress | null {
  try {
    const envelope: unknown = JSON.parse(serialized)
    if (!isRecord(envelope) || envelope.type !== "sing_box_install") {
      return null
    }
    const data: unknown = envelope.data
    if (!isRecord(data)) return null
    // Every field required and typed. A frame from a newer daemon that means
    // something else must be ignored, not rendered as a step whose name this
    // page invented.
    if (typeof data.phase !== "string" || typeof data.active !== "boolean") {
      return null
    }
    return {
      phase: data.phase,
      active: data.active,
      pinnedVersion:
        typeof data.pinned_version === "string" ? data.pinned_version : "",
      outcome: typeof data.outcome === "string" ? data.outcome : "",
    }
  } catch {
    return null
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

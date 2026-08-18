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
  // Bytes of the current download, when there is a download and the daemon has
  // seen any. Absent otherwise - a phase that transfers nothing has no bytes,
  // and inventing zero would render as a bar stuck at the start.
  receivedBytes?: number
  // The whole body's size, present only when the server said what it is. A
  // chunked response has no size to report, and a client that divided by a
  // missing one would show a percentage nobody measured.
  totalBytes?: number
}

export type SingBoxInstallState = {
  // Non-null only while an install is under way.
  progress: SingBoxInstallProgress | null
  // How the last install ended, or null if one has started since. Kept rather
  // than discarded because "aborted" is the daemon's way of saying the request
  // died after the install was already under way - the one case where a failed
  // request may nonetheless have replaced the binary, and nothing else says so.
  lastOutcome: string | null
}

type Listener = (state: SingBoxInstallState) => void

const listeners = new Set<Listener>()
let current: SingBoxInstallProgress | null = null
let lastOutcome: string | null = null

function snapshot(): SingBoxInstallState {
  return { progress: current, lastOutcome }
}

function notify() {
  const state = snapshot()
  for (const listener of listeners) listener(state)
}

export function subscribeSingBoxInstall(listener: Listener) {
  listeners.add(listener)
  // The stream replays its last frame to a new subscriber, but a component
  // already mounted when that frame arrived would otherwise never see it.
  listener(snapshot())
  return () => {
    listeners.delete(listener)
  }
}

export function getSingBoxInstallProgress() {
  return current
}

export function getSingBoxInstallLastOutcome() {
  return lastOutcome
}

export function applySingBoxInstallStatusEvent(serialized: string): boolean {
  const parsed = parse(serialized)
  if (!parsed) return false
  if (parsed.active) {
    current = parsed
    // A new install supersedes how the previous one ended, so an outcome
    // cannot leak across attempts.
    lastOutcome = null
  } else {
    // A finished install stops being progress rather than becoming progress
    // that says "finished" forever. What the install RETURNED is reported by
    // the response to the request that asked for it; this stream answers only
    // "is one running, where is it, and how did the last one end".
    current = null
    lastOutcome = parsed.outcome
  }
  notify()
  return true
}

// Called by the status-event bridge every time the stream connects, and by
// tests. On connect this is what stops a belief formed over a previous
// connection from outliving it: the daemon replays what is still true
// immediately afterwards, so clearing first is safe, and not clearing leaves a
// page that watched an install through a daemon restart convinced it is still
// running.
export function resetSingBoxInstallProgress() {
  current = null
  lastOutcome = null
  notify()
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
      ...(typeof data.received_bytes === "number"
        ? { receivedBytes: data.received_bytes }
        : {}),
      ...(typeof data.total_bytes === "number"
        ? { totalBytes: data.total_bytes }
        : {}),
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

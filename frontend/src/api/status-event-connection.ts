import { useSyncExternalStore } from "react"

export type StatusEventConnectionState =
  | "connecting"
  | "connected"
  | "disconnected"
  | "paused"

let currentState: StatusEventConnectionState = "connecting"
const listeners = new Set<() => void>()
const keepAliveListeners = new Set<() => void>()
let keepAliveLeases = 0

export function getStatusEventConnectionState() {
  return currentState
}

export function subscribeStatusEventConnectionState(listener: () => void) {
  listeners.add(listener)
  return () => {
    listeners.delete(listener)
  }
}

export function hasStatusEventKeepAliveLease() {
  return keepAliveLeases > 0
}

export function subscribeStatusEventKeepAliveLease(listener: () => void) {
  keepAliveListeners.add(listener)
  return () => {
    keepAliveListeners.delete(listener)
  }
}

export function acquireStatusEventKeepAliveLease() {
  keepAliveLeases += 1
  for (const listener of keepAliveListeners) listener()

  let released = false
  return () => {
    if (released) return
    released = true
    keepAliveLeases = Math.max(0, keepAliveLeases - 1)
    for (const listener of keepAliveListeners) listener()
  }
}

export function setStatusEventConnectionState(
  nextState: StatusEventConnectionState
) {
  if (currentState === nextState) return
  currentState = nextState
  for (const listener of listeners) listener()
}

export function useStatusEventConnectionState() {
  return useSyncExternalStore<StatusEventConnectionState>(
    subscribeStatusEventConnectionState,
    getStatusEventConnectionState,
    () => "connecting" as const
  )
}

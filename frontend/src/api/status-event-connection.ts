import { useSyncExternalStore } from "react"

export type StatusEventConnectionState =
  | "connecting"
  | "connected"
  | "disconnected"
  | "paused"

let currentState: StatusEventConnectionState = "connecting"
const listeners = new Set<() => void>()

export function setStatusEventConnectionState(
  nextState: StatusEventConnectionState
) {
  if (currentState === nextState) return
  currentState = nextState
  for (const listener of listeners) listener()
}

export function useStatusEventConnectionState() {
  return useSyncExternalStore<StatusEventConnectionState>(
    (listener) => {
      listeners.add(listener)
      return () => {
        listeners.delete(listener)
      }
    },
    () => currentState,
    () => "connecting" as const
  )
}

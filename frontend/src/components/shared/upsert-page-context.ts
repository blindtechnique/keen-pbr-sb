import { createContext, useContext } from "react"

export const UpsertCloseContext = createContext<() => void>(() => undefined)

export function useUpsertPageClose() {
  return useContext(UpsertCloseContext)
}

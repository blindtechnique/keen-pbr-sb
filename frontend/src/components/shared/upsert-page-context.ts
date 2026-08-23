import { createContext, useContext } from "react"

type UpsertPageActions = {
  readonly close: () => void
  readonly complete: () => void
}

const noop = () => undefined

export const UpsertCloseContext = createContext<UpsertPageActions>({
  close: noop,
  complete: noop,
})

export function useUpsertPageClose() {
  return useContext(UpsertCloseContext).close
}

/** Close after durable work has left the form, without a false discard prompt. */
export function useUpsertPageComplete() {
  return useContext(UpsertCloseContext).complete
}

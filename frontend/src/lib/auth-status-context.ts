import { createContext, useContext } from "react"

import type { AuthStatus } from "@/lib/auth-status"

export const AuthStatusContext = createContext<AuthStatus | null>(null)
export const TrustedLocalConnectionRevocationContext = createContext<
  () => void
>(() => undefined)

export function useTrustedAuthStatus(): AuthStatus | null {
  return useContext(AuthStatusContext)
}

export function useRevokeTrustedLocalConnection(): () => void {
  return useContext(TrustedLocalConnectionRevocationContext)
}

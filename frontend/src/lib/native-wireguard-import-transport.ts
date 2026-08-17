import type { AuthStatus } from "@/lib/auth-status"

export type NativeWireGuardImportTransport = {
  readonly protocol: string
  readonly secureContext: boolean
  readonly authEnabled: boolean
  readonly authenticated: boolean
  readonly trustedLocalConnection: boolean
}

// A .conf can contain long-lived private keys. Merely authenticating an HTTP
// page does not protect its JavaScript from WAN interception and replacement.
// Keep file selection unavailable unless the browser proves HTTPS or the
// authenticated server derives a trusted local connection from the accepted
// socket plus current NDMS/private-interface evidence. Browser address ranges,
// Host and forwarding headers never establish that server-side capability.
export function nativeWireGuardImportTransportIsProtected(
  transport: NativeWireGuardImportTransport
): boolean {
  return (
    transport.authEnabled &&
    transport.authenticated &&
    ((transport.protocol === "https:" && transport.secureContext) ||
      transport.trustedLocalConnection)
  )
}

export function currentNativeWireGuardImportTransportIsProtected(
  authStatus: AuthStatus | null
): boolean {
  if (typeof window === "undefined") return false
  return nativeWireGuardImportTransportIsProtected({
    protocol: window.location.protocol,
    secureContext: window.isSecureContext === true,
    authEnabled: authStatus?.enabled === true,
    authenticated: authStatus?.authenticated === true,
    trustedLocalConnection:
      authStatus?.trustedLocalConnection === true &&
      authStatus.trustedLocalConnectionGeneration !== null &&
      Date.now() < authStatus.trustedLocalConnectionValidUntilMs,
  })
}

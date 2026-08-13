export type AuthStatus = Readonly<{
  enabled: boolean
  authenticated: boolean
  provider: "local" | "keenetic" | null
  /** Socket/NDMS-derived by the server; absent means fail closed. */
  trustedLocalConnection: boolean
  trustedLocalConnectionGeneration: string | null
  trustedLocalConnectionValidUntilMs: number
  noAuthScope: "loopback_only" | null
  networkApiBlocked: boolean
  error?: string
}>

export type KeeneticEndpointMode = "auto" | "manual"

export function confirmAuthEnabledChange(
  currentEnabled: boolean,
  nextEnabled: boolean,
  confirmDisable: () => boolean
): boolean {
  return !currentEnabled || nextEnabled || confirmDisable()
}

export function authSettingsRestartRequired(value: unknown): boolean {
  return (
    typeof value === "object" &&
    value !== null &&
    "restart_required" in value &&
    value.restart_required === true
  )
}

export function authEndpointModeLabelKey(mode: KeeneticEndpointMode) {
  return mode === "manual"
    ? ("pages.settings.auth.endpointModeManual" as const)
    : ("pages.settings.auth.endpointModeAuto" as const)
}

/**
 * Credentials for the Keenetic provider may exist in the DOM only while the
 * server's short-lived socket/NDMS proof is current. Local-provider passwords
 * remain governed by the ordinary authenticated session boundary.
 */
export function authCredentialsMayBeCollected(
  status: AuthStatus | null,
  nowMs = Date.now()
): boolean {
  return (
    status !== null &&
    status.error === undefined &&
    (status.provider === "local" ||
      (status.provider === "keenetic" &&
        status.trustedLocalConnection &&
        status.trustedLocalConnectionGeneration !== null &&
        nowMs < status.trustedLocalConnectionValidUntilMs))
  )
}

/**
 * Refresh the same-origin socket verdict immediately before serialising a
 * Keenetic password. This closes the Wi-Fi-to-WAN gap between a periodic
 * status poll and the credential-bearing POST.
 */
export async function refreshCredentialTransportStatus(
  fetchImpl: typeof fetch = fetch,
  clock: () => number = Date.now
): Promise<AuthStatus | null> {
  try {
    // The proof lifetime starts no later than request dispatch. A slow
    // response must consume that lifetime instead of creating a fresh five
    // seconds only after the bytes finally arrive.
    const startedAtMs = clock()
    const response = await fetchImpl(
      "/api/auth/status?credential_transport=1",
      {
        cache: "no-store",
        credentials: "same-origin",
      }
    )
    if (!response.ok) return null
    const status = parseAuthStatus(await response.json(), startedAtMs)
    const validationNowMs = clock()
    return status && authCredentialsMayBeCollected(status, validationNowMs)
      ? status
      : null
  } catch {
    return null
  }
}

/**
 * Auth-settings bodies can switch from the local provider to Keenetic, so the
 * current provider cannot relax their transport boundary. Require a fresh
 * trusted-local proof regardless of what /auth/status currently names.
 */
export async function refreshTrustedLocalCredentialTransport(
  fetchImpl: typeof fetch = fetch,
  clock: () => number = Date.now
): Promise<AuthStatus | null> {
  try {
    const startedAtMs = clock()
    const response = await fetchImpl(
      "/api/auth/status?credential_transport=1",
      {
        cache: "no-store",
        credentials: "same-origin",
      }
    )
    if (!response.ok) return null
    const status = parseAuthStatus(await response.json(), startedAtMs)
    const validationNowMs = clock()
    return status &&
      status.error === undefined &&
      status.trustedLocalConnection &&
      status.trustedLocalConnectionGeneration !== null &&
      validationNowMs < status.trustedLocalConnectionValidUntilMs
      ? status
      : null
  } catch {
    return null
  }
}

export function parseAuthStatus(
  value: unknown,
  nowMs = Date.now()
): AuthStatus | null {
  if (
    typeof value !== "object" ||
    value === null ||
    !("enabled" in value) ||
    !("authenticated" in value) ||
    typeof value.enabled !== "boolean" ||
    typeof value.authenticated !== "boolean"
  ) {
    return null
  }
  const generation =
    "trusted_local_connection_generation" in value &&
    typeof value.trusted_local_connection_generation === "string" &&
    /^[1-9][0-9]{0,19}$/.test(value.trusted_local_connection_generation)
      ? value.trusted_local_connection_generation
      : null
  const validForSeconds =
    "trusted_local_connection_valid_for_seconds" in value &&
    typeof value.trusted_local_connection_valid_for_seconds === "number" &&
    Number.isInteger(value.trusted_local_connection_valid_for_seconds) &&
    value.trusted_local_connection_valid_for_seconds >= 1 &&
    value.trusted_local_connection_valid_for_seconds <= 60
      ? value.trusted_local_connection_valid_for_seconds
      : 0
  const trustedLocalConnection =
    "trusted_local_connection" in value &&
    value.trusted_local_connection === true &&
    generation !== null &&
    validForSeconds > 0 &&
    Number.isFinite(nowMs)

  return {
    enabled: value.enabled,
    authenticated: value.authenticated,
    provider:
      "provider" in value &&
      (value.provider === "local" || value.provider === "keenetic")
        ? value.provider
        : null,
    trustedLocalConnection,
    trustedLocalConnectionGeneration: trustedLocalConnection
      ? generation
      : null,
    trustedLocalConnectionValidUntilMs: trustedLocalConnection
      ? nowMs + validForSeconds * 1000
      : 0,
    noAuthScope:
      "no_auth_scope" in value && value.no_auth_scope === "loopback_only"
        ? "loopback_only"
        : null,
    networkApiBlocked:
      "network_api_blocked" in value && value.network_api_blocked === true,
    error:
      "error" in value && typeof value.error === "string"
        ? value.error
        : undefined,
  }
}

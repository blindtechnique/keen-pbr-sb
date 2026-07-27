export type AuthStatus = Readonly<{
  enabled: boolean
  authenticated: boolean
  error?: string
}>

export type KeeneticEndpointMode = "auto" | "manual"

export function authEndpointModeLabelKey(mode: KeeneticEndpointMode) {
  return mode === "manual"
    ? ("pages.settings.auth.endpointModeManual" as const)
    : ("pages.settings.auth.endpointModeAuto" as const)
}

export function parseAuthStatus(value: unknown): AuthStatus | null {
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
  return {
    enabled: value.enabled,
    authenticated: value.authenticated,
    error:
      "error" in value && typeof value.error === "string"
        ? value.error
        : undefined,
  }
}

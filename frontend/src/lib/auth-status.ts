export type AuthStatus = Readonly<{
  enabled: boolean
  authenticated: boolean
}>

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
  }
}

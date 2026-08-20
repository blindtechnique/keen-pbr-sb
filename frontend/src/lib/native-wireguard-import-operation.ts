export type NativeWireGuardImportOperationView = Readonly<{
  status:
    | "idle"
    | "preflighting"
    | "sending"
    | "preflight-error"
    | "selection-expired"
    | "unknown"
    | "recovery-locked"
    | "result"
  outcome?: "blocked" | "recovery_required" | "completed"
}>

export const nativeWireGuardImportOperationIsInFlight = (
  operation: NativeWireGuardImportOperationView
): boolean =>
  operation.status === "preflighting" || operation.status === "sending"

export const nativeWireGuardImportOperationIsWriteLocked = (
  operation: NativeWireGuardImportOperationView
): boolean =>
  operation.status === "unknown" ||
  operation.status === "recovery-locked" ||
  (operation.status === "result" && operation.outcome === "recovery_required")

export const nativeWireGuardImportOperationSurvivesContextChange = (
  operation: NativeWireGuardImportOperationView
): boolean =>
  nativeWireGuardImportOperationIsInFlight(operation) ||
  nativeWireGuardImportOperationIsWriteLocked(operation) ||
  operation.status === "result"

export const nativeWireGuardImportIntakeIsLocked = (
  operation: NativeWireGuardImportOperationView
): boolean =>
  nativeWireGuardImportOperationIsInFlight(operation) ||
  nativeWireGuardImportOperationIsWriteLocked(operation)

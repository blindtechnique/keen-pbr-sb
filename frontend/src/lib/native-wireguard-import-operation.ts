export type NativeWireGuardImportOperationView = Readonly<{
  status:
    | "idle"
    | "preflighting"
    | "sending"
    | "preflight-error"
    | "not-imported"
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

// Once the one-shot body has been handed off, these states can only be
// completed by the page-level bodyless reconciler. Keeping the create dialog
// open adds no useful action and used to delay route binding until the operator
// closed it manually.
export const nativeWireGuardImportShouldContinueInBackground = (
  operation: NativeWireGuardImportOperationView
): boolean => nativeWireGuardImportOperationIsWriteLocked(operation)

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

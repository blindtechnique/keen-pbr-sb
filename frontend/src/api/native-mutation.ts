import { fetchWithStepUp } from "@/lib/step-up"

export const NDMS_NATIVE_DELETE_PATH = "/api/system/ndms/interfaces/remove"
export const NDMS_NATIVE_DELETE_RECOVERY_PATH =
  "/api/system/ndms/interfaces/remove/recovery/retry"
export const NDMS_NATIVE_IMPORT_RECOVERY_PATH =
  "/api/system/ndms/interfaces/import/recovery/retry"

export const NDMS_NATIVE_DELETE_STATUSES = [
  "blocked",
  "recovery_required",
  "save_acknowledged_unverified",
] as const

export const NDMS_NATIVE_DELETE_STOPS = [
  "none",
  "owner_global_save_not_acknowledged",
  "external_writer_race_not_accepted",
  "save_reconfirmation_required",
  "writer_missing",
  "writer_lost",
  "invalid_or_protected_target",
  "import_wal_not_authoritatively_clean",
  "delete_wal_unfinished",
  "delete_wal_unsafe",
  "no_delete_transaction",
  "ownership_absent",
  "ownership_unreadable",
  "ownership_not_active",
  "ownership_changed",
  "snapshot_absent",
  "snapshot_unreadable",
  "snapshot_mismatch",
  "keen_pbr_dependency_scan_incomplete",
  "keen_pbr_dependencies_present",
  "keen_pbr_dependency_changed",
  "runtime_observation_failed",
  "running_config_observation_failed",
  "observation_scope_mismatch",
  "observed_target_mismatch",
  "observed_target_drifted",
  "observed_target_reappeared_after_save",
  "durable_observation_failed",
  "delete_wal_publish_failed",
  "delete_guard_rejected",
  "delete_transport_ambiguous",
  "save_guard_rejected",
  "save_transport_ambiguous",
  "tombstone_publish_failed",
  "tombstone_mismatch",
  "delete_wal_cleanup_failed",
  "unexpected_failure",
] as const

const deletePhases = [
  "prepared",
  "delete_may_be_inflight",
  "running_absence_verified",
  "save_may_be_inflight",
  "save_acknowledged_unverified",
  "cleanup",
] as const
const transportOutcomes = [
  "guard_rejected",
  "transport_failed",
  "body_too_large",
  "http_status_not_200",
  "content_type_not_json",
  "body_empty",
  "shape_not_acknowledged",
  "acknowledged_needs_observation",
] as const
const observationFailures = [
  "none",
  "invalid_marker",
  "invalid_target",
  "transport_failed",
  "response_too_large",
  "empty_response",
  "malformed_json",
  "duplicate_json_key",
  "response_not_object",
  "rci_error_response",
  "catalog_malformed",
  "catalog_unavailable",
  "catalog_unsafe",
  "ambiguous_marker",
  "marker_target_not_managed_wireguard",
  "target_evidence_refused",
] as const
const importKinds = ["wireguard", "amnezia_wireguard"] as const
const walReadiness = ["clean", "unfinished", "unsafe"] as const

export type NdmsNativeDeleteStatus =
  (typeof NDMS_NATIVE_DELETE_STATUSES)[number]
export type NdmsNativeDeleteStop = (typeof NDMS_NATIVE_DELETE_STOPS)[number]

export type NdmsNativeDeleteResult = Readonly<{
  status: NdmsNativeDeleteStatus
  stop: NdmsNativeDeleteStop
  external_writer_race_excluded: false
  external_writer_race_accepted: boolean
  global_save_scope_acknowledged: boolean
  delete_perform_started: boolean
  save_perform_started: boolean
  request_may_have_been_dispatched: boolean
  system_configuration_save_acknowledged: boolean
  ownership_tombstone_durable: boolean
  rollback_snapshot_retained: boolean
  phase?: (typeof deletePhases)[number]
  interface_name?: string
  kind?: (typeof importKinds)[number]
  transport_outcome?: (typeof transportOutcomes)[number]
  observation_failure?: (typeof observationFailures)[number]
}>

export type NdmsNativeDeleteRequest = Readonly<{
  interface_name: string
  expected_ownership_revision: string
  confirm_label: string
}>

export const NDMS_NATIVE_IMPORT_RECOVERY_STATUSES = [
  "no_work",
  "blocked",
  "completed",
] as const
export const NDMS_NATIVE_IMPORT_RECOVERY_STOPS = [
  "none",
  "writer_missing",
  "writer_lost",
  "delete_wal_not_clean",
  "import_wal_not_single_safe",
  "record_not_cooperative",
  "phase_not_forward_only",
  "expected_target_not_managed",
  "first_observation_failed",
  "second_observation_failed",
  "observation_kind_mismatch",
  "durable_observation_failed",
  "observation_unstable",
  "ownership_not_exact",
  "recovery_action_not_forward_only",
  "forward_admission_failed",
  "target_verified_wal_publish_failed",
  "ownership_publish_failed",
  "ownership_wal_publish_failed",
  "wal_cleanup_failed",
  "unexpected_failure",
] as const
const importPhases = [
  "prepared",
  "import_may_be_inflight",
  "response_recorded",
  "target_verified",
  "ownership_published",
  "rollback_requested",
  "delete_may_be_inflight",
  "absence_verified",
] as const
const importRecoveryActions = [
  "retry_read_only_observation",
  "abort_without_mutation",
  "rollback_delete_exact_owned",
  "resume_forward_reconcile",
  "retry_exact_owned_delete",
  "complete_rollback",
  "block_unknown",
] as const
const importRecoveryAdmissionStates = [
  "admitted",
  "lease_busy",
  "lease_io_error",
  "inventory_not_ready",
  "record_missing",
  "record_changed",
  "action_not_actionable",
] as const
const importRecoveryDispatchStates = [
  "completed",
  "lease_not_held",
  "plan_empty",
  "target_missing",
  "target_not_eligible",
  "ownership_store_missing",
  "snapshot_retirer_missing",
  "step_failed",
] as const
const importRecoverySteps = [
  "advance_wal_target_verified",
  "publish_ownership",
  "advance_wal_ownership_published",
  "advance_wal_rollback_requested",
  "remove_ownership_claim",
  "advance_wal_delete_may_be_inflight",
  "delete_exact_owned_target",
  "advance_wal_absence_verified",
  "remove_wal_record",
] as const

export type NdmsNativeImportRecoveryStatus =
  (typeof NDMS_NATIVE_IMPORT_RECOVERY_STATUSES)[number]
export type NdmsNativeImportRecoveryStop =
  (typeof NDMS_NATIVE_IMPORT_RECOVERY_STOPS)[number]
export type NdmsNativeImportRecoveryResult = Readonly<{
  status: NdmsNativeImportRecoveryStatus
  stop: NdmsNativeImportRecoveryStop
  ndms_import_request_dispatched: false
  ndms_delete_dispatched: false
  system_configuration_save_performed: false
  external_ndms_writer_race_excluded: false
  wal_may_require_recovery: boolean
  ownership_published: boolean
  wal_removed: boolean
  expected_interface?: string
  created_interface?: string
  created_kernel_interface?: string
  kind?: (typeof importKinds)[number]
  phase?: (typeof importPhases)[number]
  delete_wal_readiness?: (typeof walReadiness)[number]
  import_wal_readiness?: (typeof walReadiness)[number]
  direct_observation_failure?: (typeof observationFailures)[number]
  recovery_action?: (typeof importRecoveryActions)[number]
  forward_admission_state?: (typeof importRecoveryAdmissionStates)[number]
  forward_dispatch_state?: (typeof importRecoveryDispatchStates)[number]
  forward_failed_step?: (typeof importRecoverySteps)[number]
}>

export class NativeMutationTransportError extends Error {
  readonly code: "rejected" | "outcome_unknown"

  constructor(code: "rejected" | "outcome_unknown") {
    super(code)
    this.name = "NativeMutationTransportError"
    this.code = code
  }
}

const deleteAllowedKeys = new Set([
  "status",
  "stop",
  "external_writer_race_excluded",
  "external_writer_race_accepted",
  "global_save_scope_acknowledged",
  "delete_perform_started",
  "save_perform_started",
  "request_may_have_been_dispatched",
  "system_configuration_save_acknowledged",
  "ownership_tombstone_durable",
  "rollback_snapshot_retained",
  "phase",
  "interface_name",
  "kind",
  "transport_outcome",
  "observation_failure",
])

const importRecoveryAllowedKeys = new Set([
  "status",
  "stop",
  "ndms_import_request_dispatched",
  "ndms_delete_dispatched",
  "system_configuration_save_performed",
  "external_ndms_writer_race_excluded",
  "wal_may_require_recovery",
  "ownership_published",
  "wal_removed",
  "expected_interface",
  "created_interface",
  "created_kernel_interface",
  "kind",
  "phase",
  "delete_wal_readiness",
  "import_wal_readiness",
  "direct_observation_failure",
  "recovery_action",
  "forward_admission_state",
  "forward_dispatch_state",
  "forward_failed_step",
])

const inList = <T extends string>(
  value: unknown,
  values: readonly T[]
): value is T => typeof value === "string" && values.includes(value as T)

const validFirmwareInterface = (value: unknown): value is string =>
  typeof value === "string" &&
  /^Wireguard(?:[5-9]|[1-8][0-9]|9[0-8])$/.test(value)

const validKernelInterface = (value: unknown): value is string =>
  typeof value === "string" &&
  value !== "." &&
  value !== ".." &&
  /^[A-Za-z0-9_.:-]{1,15}$/.test(value)

const validOwnershipRevision = (value: unknown): value is string =>
  typeof value === "string" &&
  /^ndms-native-owner-(?:v2|v3|tombstone-v1)-[0-9a-f]{64}$/.test(value)

const isRecord = (payload: unknown): payload is Record<string, unknown> =>
  Boolean(payload) && typeof payload === "object" && !Array.isArray(payload)

export function parseNdmsNativeDeleteResult(
  payload: unknown
): NdmsNativeDeleteResult | null {
  if (!isRecord(payload)) return null
  const value = payload
  if (Object.keys(value).some((key) => !deleteAllowedKeys.has(key))) return null
  if (
    !inList(value.status, NDMS_NATIVE_DELETE_STATUSES) ||
    !inList(value.stop, NDMS_NATIVE_DELETE_STOPS) ||
    value.external_writer_race_excluded !== false ||
    typeof value.external_writer_race_accepted !== "boolean" ||
    typeof value.global_save_scope_acknowledged !== "boolean" ||
    typeof value.delete_perform_started !== "boolean" ||
    typeof value.save_perform_started !== "boolean" ||
    typeof value.request_may_have_been_dispatched !== "boolean" ||
    typeof value.system_configuration_save_acknowledged !== "boolean" ||
    typeof value.ownership_tombstone_durable !== "boolean" ||
    typeof value.rollback_snapshot_retained !== "boolean" ||
    (value.phase !== undefined && !inList(value.phase, deletePhases)) ||
    (value.interface_name !== undefined &&
      !validFirmwareInterface(value.interface_name)) ||
    (value.kind !== undefined && !inList(value.kind, importKinds)) ||
    (value.transport_outcome !== undefined &&
      !inList(value.transport_outcome, transportOutcomes)) ||
    (value.observation_failure !== undefined &&
      !inList(value.observation_failure, observationFailures))
  ) {
    return null
  }

  const identityFields = [value.phase, value.interface_name, value.kind]
  const hasAnyIdentity = identityFields.some((field) => field !== undefined)
  const hasIdentity = identityFields.every((field) => field !== undefined)
  if (
    hasAnyIdentity !== hasIdentity ||
    value.external_writer_race_accepted !==
      value.global_save_scope_acknowledged ||
    hasIdentity !== value.external_writer_race_accepted
  ) {
    return null
  }

  const terminal = value.status === "save_acknowledged_unverified"
  if (
    terminal &&
    (value.stop !== "none" ||
      value.phase !== "cleanup" ||
      !hasIdentity ||
      value.ownership_tombstone_durable !== true ||
      value.rollback_snapshot_retained !== true ||
      value.observation_failure !== undefined)
  ) {
    return null
  }
  if (
    !terminal &&
    (value.stop === "none" ||
      value.ownership_tombstone_durable !== false ||
      value.rollback_snapshot_retained !== false)
  ) {
    return null
  }

  const anyPerformStarted =
    value.delete_perform_started || value.save_perform_started
  if (
    anyPerformStarted !== value.request_may_have_been_dispatched ||
    ((anyPerformStarted || value.system_configuration_save_acknowledged) &&
      value.transport_outcome === undefined) ||
    (value.transport_outcome !== undefined &&
      value.transport_outcome !== "guard_rejected" &&
      value.transport_outcome !== "transport_failed" &&
      !anyPerformStarted) ||
    (value.system_configuration_save_acknowledged &&
      (!value.save_perform_started ||
        value.transport_outcome !== "acknowledged_needs_observation"))
  ) {
    return null
  }
  if (
    value.status === "blocked" &&
    (anyPerformStarted ||
      value.system_configuration_save_acknowledged ||
      value.transport_outcome !== undefined ||
      (value.phase !== undefined && value.phase !== "prepared"))
  ) {
    return null
  }
  if (
    value.observation_failure !== undefined &&
    value.stop !== "runtime_observation_failed" &&
    value.stop !== "running_config_observation_failed"
  ) {
    return null
  }
  if (terminal && value.delete_perform_started && !value.save_perform_started) {
    return null
  }
  if (
    terminal &&
    value.transport_outcome !== undefined &&
    value.transport_outcome !== "acknowledged_needs_observation"
  ) {
    return null
  }
  if (
    terminal &&
    value.save_perform_started !== value.system_configuration_save_acknowledged
  ) {
    return null
  }
  return value as NdmsNativeDeleteResult
}

const forwardOnlyPhase = (value: unknown): boolean =>
  value === "response_recorded" ||
  value === "target_verified" ||
  value === "ownership_published"

const forwardOnlyStep = (value: unknown): boolean =>
  value === "advance_wal_target_verified" ||
  value === "publish_ownership" ||
  value === "advance_wal_ownership_published" ||
  value === "remove_wal_record"

export function parseNdmsNativeImportRecoveryResult(
  payload: unknown
): NdmsNativeImportRecoveryResult | null {
  if (!isRecord(payload)) return null
  const value = payload
  if (Object.keys(value).some((key) => !importRecoveryAllowedKeys.has(key))) {
    return null
  }
  if (
    !inList(value.status, NDMS_NATIVE_IMPORT_RECOVERY_STATUSES) ||
    !inList(value.stop, NDMS_NATIVE_IMPORT_RECOVERY_STOPS) ||
    value.ndms_import_request_dispatched !== false ||
    value.ndms_delete_dispatched !== false ||
    value.system_configuration_save_performed !== false ||
    value.external_ndms_writer_race_excluded !== false ||
    typeof value.wal_may_require_recovery !== "boolean" ||
    typeof value.ownership_published !== "boolean" ||
    typeof value.wal_removed !== "boolean" ||
    (value.expected_interface !== undefined &&
      !validFirmwareInterface(value.expected_interface)) ||
    (value.created_interface !== undefined &&
      !validFirmwareInterface(value.created_interface)) ||
    (value.created_kernel_interface !== undefined &&
      !validKernelInterface(value.created_kernel_interface)) ||
    (value.kind !== undefined && !inList(value.kind, importKinds)) ||
    (value.phase !== undefined && !inList(value.phase, importPhases)) ||
    (value.delete_wal_readiness !== undefined &&
      !inList(value.delete_wal_readiness, walReadiness)) ||
    (value.import_wal_readiness !== undefined &&
      !inList(value.import_wal_readiness, walReadiness)) ||
    (value.direct_observation_failure !== undefined &&
      !inList(value.direct_observation_failure, observationFailures)) ||
    (value.recovery_action !== undefined &&
      !inList(value.recovery_action, importRecoveryActions)) ||
    (value.forward_admission_state !== undefined &&
      !inList(value.forward_admission_state, importRecoveryAdmissionStates)) ||
    (value.forward_dispatch_state !== undefined &&
      !inList(value.forward_dispatch_state, importRecoveryDispatchStates)) ||
    (value.forward_failed_step !== undefined &&
      !inList(value.forward_failed_step, importRecoverySteps))
  ) {
    return null
  }

  const recordFields = [value.expected_interface, value.kind, value.phase]
  const hasAnyRecord = recordFields.some((field) => field !== undefined)
  const hasRecord = recordFields.every((field) => field !== undefined)
  const hasAnyCreated =
    value.created_interface !== undefined ||
    value.created_kernel_interface !== undefined
  const hasCreated =
    value.created_interface !== undefined &&
    value.created_kernel_interface !== undefined
  if (
    hasAnyRecord !== hasRecord ||
    hasAnyCreated !== hasCreated ||
    (hasCreated && value.created_interface !== value.expected_interface) ||
    (hasRecord &&
      (value.delete_wal_readiness !== "clean" ||
        value.import_wal_readiness !== "unfinished"))
  ) {
    return null
  }

  const observationFailed =
    value.stop === "first_observation_failed" ||
    value.stop === "second_observation_failed"
  if (
    observationFailed !== (value.direct_observation_failure !== undefined) ||
    value.direct_observation_failure === "none"
  ) {
    return null
  }

  const dispatchFailed = value.forward_dispatch_state === "step_failed"
  if (
    dispatchFailed !== (value.forward_failed_step !== undefined) ||
    (value.forward_failed_step !== undefined &&
      !forwardOnlyStep(value.forward_failed_step)) ||
    (value.forward_dispatch_state !== undefined &&
      value.forward_admission_state !== "admitted")
  ) {
    return null
  }
  const hasForwardEvidence =
    value.recovery_action !== undefined ||
    value.forward_admission_state !== undefined ||
    value.forward_dispatch_state !== undefined ||
    value.forward_failed_step !== undefined
  if (
    (!hasRecord &&
      (hasCreated || value.ownership_published || hasForwardEvidence)) ||
    (value.ownership_published && !hasCreated) ||
    (value.wal_removed && value.status !== "completed") ||
    ((hasCreated || value.ownership_published || hasForwardEvidence) &&
      !forwardOnlyPhase(value.phase))
  ) {
    return null
  }

  if (
    value.status === "no_work" &&
    (value.stop !== "none" ||
      hasRecord ||
      hasCreated ||
      value.delete_wal_readiness !== "clean" ||
      value.import_wal_readiness !== "clean" ||
      value.wal_may_require_recovery ||
      value.ownership_published ||
      value.wal_removed ||
      hasForwardEvidence)
  ) {
    return null
  }
  if (
    value.status === "blocked" &&
    (value.stop === "none" ||
      value.wal_removed ||
      hasRecord !== value.wal_may_require_recovery ||
      value.forward_dispatch_state === "completed")
  ) {
    return null
  }
  if (
    value.status === "completed" &&
    (value.stop !== "none" ||
      !hasRecord ||
      !hasCreated ||
      !forwardOnlyPhase(value.phase) ||
      value.wal_may_require_recovery ||
      !value.ownership_published ||
      !value.wal_removed ||
      value.forward_admission_state !== "admitted" ||
      value.forward_dispatch_state !== "completed" ||
      value.forward_failed_step !== undefined ||
      (value.phase === "ownership_published") !==
        (value.recovery_action === "resume_forward_reconcile"))
  ) {
    return null
  }
  return value as NdmsNativeImportRecoveryResult
}

const commonRequestInit = {
  method: "POST",
  cache: "no-store",
  credentials: "same-origin",
  keepalive: false,
  mode: "same-origin",
  redirect: "error",
  referrerPolicy: "no-referrer",
} as const satisfies RequestInit

const parseTrustedResponse = async <T>(
  response: Response,
  parser: (payload: unknown) => T | null
): Promise<T> => {
  if (!response.ok) {
    // These statuses are emitted before the typed mutation callback. A 5xx,
    // 503/proxy failure, redirect or any unexpected status cannot prove that
    // the router was untouched and therefore remains outcome-unknown.
    const preCoreRejection = [400, 401, 403, 413, 415, 428].includes(
      response.status
    )
    throw new NativeMutationTransportError(
      preCoreRejection ? "rejected" : "outcome_unknown"
    )
  }
  const payload = await response.json().catch(() => null)
  const parsed = parser(payload)
  if (!parsed) throw new NativeMutationTransportError("outcome_unknown")
  return parsed
}

export async function postNdmsNativeDeleteOnce(
  request: NdmsNativeDeleteRequest,
  fetchImpl: typeof fetch = fetch
): Promise<NdmsNativeDeleteResult> {
  if (
    !validFirmwareInterface(request.interface_name) ||
    request.confirm_label !== request.interface_name ||
    !validOwnershipRevision(request.expected_ownership_revision)
  ) {
    throw new NativeMutationTransportError("rejected")
  }
  const response = await fetchWithStepUp(
    NDMS_NATIVE_DELETE_PATH,
    {
      ...commonRequestInit,
      headers: {
        "Content-Type": "application/json",
        "X-Keen-Pbr-External-Ndms-Writer-Race-Acceptance": "owner-accepted",
        "X-Keen-Pbr-Global-Save-Acknowledgement":
          "owner-acknowledges-save-persists-all-pending-keenetic-changes",
      },
      body: JSON.stringify(request),
    },
    fetchImpl
  )
  const result = await parseTrustedResponse(
    response,
    parseNdmsNativeDeleteResult
  )
  if (
    result.interface_name !== undefined &&
    result.interface_name !== request.interface_name
  ) {
    throw new NativeMutationTransportError("outcome_unknown")
  }
  return result
}

export async function postNdmsNativeDeleteRecoveryOnce(
  acknowledgements: boolean,
  fetchImpl: typeof fetch = fetch
): Promise<NdmsNativeDeleteResult> {
  const response = await fetchWithStepUp(
    NDMS_NATIVE_DELETE_RECOVERY_PATH,
    {
      ...commonRequestInit,
      ...(acknowledgements
        ? {
            headers: {
              "X-Keen-Pbr-External-Ndms-Writer-Race-Acceptance":
                "owner-accepted",
              "X-Keen-Pbr-Global-Save-Acknowledgement":
                "owner-acknowledges-save-persists-all-pending-keenetic-changes",
            },
          }
        : {}),
    },
    fetchImpl
  )
  return parseTrustedResponse(response, parseNdmsNativeDeleteResult)
}

export async function postNdmsNativeImportRecoveryOnce(
  fetchImpl: typeof fetch = fetch
): Promise<NdmsNativeImportRecoveryResult> {
  const response = await fetchWithStepUp(
    NDMS_NATIVE_IMPORT_RECOVERY_PATH,
    commonRequestInit,
    fetchImpl
  )
  return parseTrustedResponse(response, parseNdmsNativeImportRecoveryResult)
}

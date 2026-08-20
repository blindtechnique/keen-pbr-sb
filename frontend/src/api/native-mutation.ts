import { fetchWithStepUp } from "@/lib/step-up"

export const NDMS_NATIVE_DELETE_PATH = "/api/system/ndms/interfaces/remove"
export const NDMS_NATIVE_DELETE_RECOVERY_PATH =
  "/api/system/ndms/interfaces/remove/recovery/retry"
export const NDMS_NATIVE_IMPORT_RECOVERY_PATH =
  "/api/system/ndms/interfaces/import/recovery/retry"
export const NDMS_NATIVE_TOMBSTONE_FORGET_PATH =
  "/api/system/ndms/interfaces/retained-deletions/forget"

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

export const NDMS_NATIVE_TOMBSTONE_FORGET_STATUSES = [
  "blocked",
  "recovery_required",
  "forgotten",
] as const
export const NDMS_NATIVE_TOMBSTONE_FORGET_STOPS = [
  "none",
  "writer_missing",
  "writer_lost",
  "import_wal_not_authoritatively_clean",
  "delete_wal_unfinished",
  "delete_wal_unsafe",
  "ownership_absent",
  "ownership_unreadable",
  "ownership_not_forget_capable",
  "ownership_changed",
  "snapshot_unreadable",
  "snapshot_mismatch",
  "snapshot_retirement_failed",
  "keen_pbr_dependency_scan_incomplete",
  "keen_pbr_dependencies_present",
  "kernel_inventory_unavailable",
  "retained_kernel_interface_present",
  "runtime_observation_failed",
  "running_config_observation_failed",
  "observation_scope_mismatch",
  "observed_target_present",
  "observed_marker_present",
  "observed_catalog_unsafe",
  "tombstone_retirement_failed",
  "unexpected_failure",
] as const
export const NDMS_NATIVE_TOMBSTONE_FORGET_ARTIFACT_STATES = [
  "unknown",
  "retained",
  "absent_durable",
] as const

export type NdmsNativeTombstoneForgetStatus =
  (typeof NDMS_NATIVE_TOMBSTONE_FORGET_STATUSES)[number]
export type NdmsNativeTombstoneForgetStop =
  (typeof NDMS_NATIVE_TOMBSTONE_FORGET_STOPS)[number]
export type NdmsNativeTombstoneForgetArtifactState =
  (typeof NDMS_NATIVE_TOMBSTONE_FORGET_ARTIFACT_STATES)[number]
export type NdmsNativeTombstoneForgetRequest = Readonly<{
  interface_name: string
  expected_ownership_revision: string
  confirm_interface_name: string
  rollback_discard_acknowledgement: "permanently_discard_rollback_data"
  foreign_reappearance_acknowledgement: "accepted_reappearance_is_foreign"
}>
export type NdmsNativeTombstoneForgetResult = Readonly<{
  status: NdmsNativeTombstoneForgetStatus
  stop: NdmsNativeTombstoneForgetStop
  interface_name: string
  snapshot_state: NdmsNativeTombstoneForgetArtifactState
  tombstone_state: NdmsNativeTombstoneForgetArtifactState
  router_mutation_attempted: false
  system_configuration_save_acknowledged: false
  future_reappearance_is_foreign: boolean
}>

export const NDMS_NATIVE_IMPORT_RECOVERY_STATUSES = [
  "no_work",
  "blocked",
  "recovery_required",
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
  "external_writer_race_not_accepted",
  "expected_target_not_managed",
  "first_observation_failed",
  "second_observation_failed",
  "observation_kind_mismatch",
  "durable_observation_failed",
  "observation_unstable",
  "ownership_not_exact",
  "snapshot_not_exact",
  "recovery_action_not_forward_only",
  "recovery_action_not_actionable",
  "forward_admission_failed",
  "recovery_admission_failed",
  "target_verified_wal_publish_failed",
  "ownership_publish_failed",
  "ownership_wal_publish_failed",
  "rollback_wal_publish_failed",
  "ownership_retract_failed",
  "delete_wal_publish_failed",
  "delete_guard_rejected",
  "delete_transport_ambiguous",
  "absence_wal_publish_failed",
  "snapshot_retirement_failed",
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
  ndms_delete_dispatched: boolean
  system_configuration_save_performed: false
  external_ndms_writer_race_excluded: false
  external_ndms_writer_race_accepted: boolean
  delete_perform_started: boolean
  request_may_have_been_dispatched: boolean
  wal_may_require_recovery: boolean
  ownership_published: boolean
  rollback_snapshot_retired: boolean
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
  recovery_admission_state?: (typeof importRecoveryAdmissionStates)[number]
  recovery_dispatch_state?: (typeof importRecoveryDispatchStates)[number]
  recovery_failed_step?: (typeof importRecoverySteps)[number]
  delete_transport_outcome?: (typeof transportOutcomes)[number]
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
  "external_ndms_writer_race_accepted",
  "delete_perform_started",
  "request_may_have_been_dispatched",
  "wal_may_require_recovery",
  "ownership_published",
  "rollback_snapshot_retired",
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
  "recovery_admission_state",
  "recovery_dispatch_state",
  "recovery_failed_step",
  "delete_transport_outcome",
])

const tombstoneForgetAllowedKeys = new Set([
  "status",
  "stop",
  "interface_name",
  "snapshot_state",
  "tombstone_state",
  "router_mutation_attempted",
  "system_configuration_save_acknowledged",
  "future_reappearance_is_foreign",
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

const validTombstoneOwnershipRevision = (value: unknown): value is string =>
  typeof value === "string" &&
  /^ndms-native-owner-tombstone-v1-[0-9a-f]{64}$/.test(value)

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

const recoveryImpossibleForgetStops = new Set<NdmsNativeTombstoneForgetStop>([
  "writer_missing",
  "ownership_absent",
  "ownership_unreadable",
  "ownership_not_forget_capable",
  "snapshot_unreadable",
  "snapshot_mismatch",
])

export function parseNdmsNativeTombstoneForgetResult(
  payload: unknown
): NdmsNativeTombstoneForgetResult | null {
  if (!isRecord(payload)) return null
  const value = payload
  if (Object.keys(value).some((key) => !tombstoneForgetAllowedKeys.has(key))) {
    return null
  }
  if (
    !inList(value.status, NDMS_NATIVE_TOMBSTONE_FORGET_STATUSES) ||
    !inList(value.stop, NDMS_NATIVE_TOMBSTONE_FORGET_STOPS) ||
    !validFirmwareInterface(value.interface_name) ||
    !inList(
      value.snapshot_state,
      NDMS_NATIVE_TOMBSTONE_FORGET_ARTIFACT_STATES
    ) ||
    !inList(
      value.tombstone_state,
      NDMS_NATIVE_TOMBSTONE_FORGET_ARTIFACT_STATES
    ) ||
    value.router_mutation_attempted !== false ||
    value.system_configuration_save_acknowledged !== false ||
    typeof value.future_reappearance_is_foreign !== "boolean"
  ) {
    return null
  }

  const result = value as unknown as NdmsNativeTombstoneForgetResult
  if (result.status === "forgotten") {
    return result.stop === "none" &&
      result.snapshot_state === "absent_durable" &&
      result.tombstone_state === "absent_durable" &&
      result.future_reappearance_is_foreign
      ? result
      : null
  }
  if (result.stop === "none" || result.future_reappearance_is_foreign) {
    return null
  }
  if (result.status === "blocked") {
    if (result.stop === "tombstone_retirement_failed") return null
    const expectedArtifactState =
      result.stop === "snapshot_retirement_failed" ? "retained" : "unknown"
    return result.snapshot_state === expectedArtifactState &&
      result.tombstone_state === expectedArtifactState
      ? result
      : null
  }

  if (recoveryImpossibleForgetStops.has(result.stop)) return null
  if (result.stop === "snapshot_retirement_failed") {
    return result.snapshot_state !== "absent_durable" ? result : null
  }
  if (result.stop === "unexpected_failure") return result
  return result.snapshot_state === "absent_durable" ? result : null
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

const destructiveRecoveryAction = (value: unknown): boolean =>
  value === "rollback_delete_exact_owned" ||
  value === "retry_exact_owned_delete"

const cleanupRecoveryAction = (value: unknown): boolean =>
  value === "abort_without_mutation" ||
  destructiveRecoveryAction(value) ||
  value === "complete_rollback"

const initiallyDispatchableRecoveryAction = (
  action: unknown,
  phase: unknown
): boolean => {
  switch (action) {
    case "abort_without_mutation":
      return (
        phase === "prepared" ||
        phase === "import_may_be_inflight" ||
        phase === "response_recorded"
      )
    case "rollback_delete_exact_owned":
      return phase === "import_may_be_inflight" || phase === "response_recorded"
    case "retry_exact_owned_delete":
      return (
        phase === "rollback_requested" || phase === "delete_may_be_inflight"
      )
    case "complete_rollback":
      return (
        phase === "target_verified" ||
        phase === "ownership_published" ||
        phase === "rollback_requested" ||
        phase === "delete_may_be_inflight" ||
        phase === "absence_verified"
      )
    default:
      return false
  }
}

const failedRecoveryStepMatchesDurablePhase = (
  action: unknown,
  phase: unknown,
  step: unknown
): boolean => {
  switch (action) {
    case "abort_without_mutation":
      return (
        step === "remove_wal_record" &&
        initiallyDispatchableRecoveryAction(action, phase)
      )
    case "rollback_delete_exact_owned":
      if (step === "advance_wal_rollback_requested") {
        return (
          phase === "import_may_be_inflight" || phase === "response_recorded"
        )
      }
      if (
        step === "remove_ownership_claim" ||
        step === "advance_wal_delete_may_be_inflight"
      ) {
        return phase === "rollback_requested"
      }
      if (
        step === "delete_exact_owned_target" ||
        step === "advance_wal_absence_verified"
      ) {
        return phase === "delete_may_be_inflight"
      }
      return step === "remove_wal_record" && phase === "absence_verified"
    case "retry_exact_owned_delete":
      if (step === "remove_ownership_claim") {
        return (
          phase === "rollback_requested" || phase === "delete_may_be_inflight"
        )
      }
      if (step === "advance_wal_delete_may_be_inflight") {
        return phase === "rollback_requested"
      }
      if (
        step === "delete_exact_owned_target" ||
        step === "advance_wal_absence_verified"
      ) {
        return phase === "delete_may_be_inflight"
      }
      return step === "remove_wal_record" && phase === "absence_verified"
    case "complete_rollback":
      if (step === "advance_wal_absence_verified") {
        return (
          phase === "target_verified" ||
          phase === "ownership_published" ||
          phase === "rollback_requested" ||
          phase === "delete_may_be_inflight"
        )
      }
      if (step === "remove_ownership_claim") {
        return (
          phase === "rollback_requested" ||
          phase === "delete_may_be_inflight" ||
          phase === "absence_verified"
        )
      }
      return step === "remove_wal_record" && phase === "absence_verified"
    default:
      return false
  }
}

const recoveryActionMatchesReportedPhase = (
  action: unknown,
  phase: unknown,
  dispatch: unknown,
  failedStep: unknown
): boolean =>
  dispatch === "step_failed"
    ? failedStep !== undefined &&
      failedRecoveryStepMatchesDurablePhase(action, phase, failedStep)
    : failedStep === undefined &&
      initiallyDispatchableRecoveryAction(action, phase)

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
    typeof value.ndms_delete_dispatched !== "boolean" ||
    value.system_configuration_save_performed !== false ||
    value.external_ndms_writer_race_excluded !== false ||
    typeof value.external_ndms_writer_race_accepted !== "boolean" ||
    typeof value.delete_perform_started !== "boolean" ||
    typeof value.request_may_have_been_dispatched !== "boolean" ||
    typeof value.wal_may_require_recovery !== "boolean" ||
    typeof value.ownership_published !== "boolean" ||
    typeof value.rollback_snapshot_retired !== "boolean" ||
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
      !inList(value.forward_failed_step, importRecoverySteps)) ||
    (value.recovery_admission_state !== undefined &&
      !inList(value.recovery_admission_state, importRecoveryAdmissionStates)) ||
    (value.recovery_dispatch_state !== undefined &&
      !inList(value.recovery_dispatch_state, importRecoveryDispatchStates)) ||
    (value.recovery_failed_step !== undefined &&
      !inList(value.recovery_failed_step, importRecoverySteps)) ||
    (value.delete_transport_outcome !== undefined &&
      !inList(value.delete_transport_outcome, transportOutcomes))
  ) {
    return null
  }

  const result = value as unknown as NdmsNativeImportRecoveryResult

  const recordFields = [result.expected_interface, result.kind, result.phase]
  const hasAnyRecord = recordFields.some((field) => field !== undefined)
  const hasRecord = recordFields.every((field) => field !== undefined)
  const hasAnyCreated =
    result.created_interface !== undefined ||
    result.created_kernel_interface !== undefined
  const hasCreated =
    result.created_interface !== undefined &&
    result.created_kernel_interface !== undefined
  if (
    hasAnyRecord !== hasRecord ||
    hasAnyCreated !== hasCreated ||
    (hasCreated && result.created_interface !== result.expected_interface) ||
    (hasRecord &&
      (result.delete_wal_readiness !== "clean" ||
        result.import_wal_readiness !== "unfinished")) ||
    (hasRecord &&
      result.status !== "completed" &&
      !result.wal_may_require_recovery) ||
    (!hasRecord &&
      (result.wal_may_require_recovery ||
        result.ownership_published ||
        result.rollback_snapshot_retired ||
        result.wal_removed)) ||
    (result.status === "completed" && result.wal_may_require_recovery)
  ) {
    return null
  }

  const observationFailed =
    result.stop === "first_observation_failed" ||
    result.stop === "second_observation_failed"
  if (
    observationFailed !== (result.direct_observation_failure !== undefined) ||
    result.direct_observation_failure === "none"
  ) {
    return null
  }

  const forwardDispatchFailed = result.forward_dispatch_state === "step_failed"
  if (
    forwardDispatchFailed !== (result.forward_failed_step !== undefined) ||
    (result.forward_failed_step !== undefined &&
      !forwardOnlyStep(result.forward_failed_step)) ||
    (result.forward_dispatch_state !== undefined &&
      result.forward_admission_state !== "admitted")
  ) {
    return null
  }
  const recoveryDispatchFailed =
    result.recovery_dispatch_state === "step_failed"
  if (
    recoveryDispatchFailed !== (result.recovery_failed_step !== undefined) ||
    (result.recovery_dispatch_state !== undefined &&
      result.recovery_admission_state !== "admitted")
  ) {
    return null
  }

  const hasForwardEvidence =
    result.forward_admission_state !== undefined ||
    result.forward_dispatch_state !== undefined ||
    result.forward_failed_step !== undefined
  const hasRecoveryEvidence =
    result.recovery_admission_state !== undefined ||
    result.recovery_dispatch_state !== undefined ||
    result.recovery_failed_step !== undefined
  if (
    (hasForwardEvidence && hasRecoveryEvidence) ||
    (!hasRecord &&
      (hasCreated ||
        result.recovery_action !== undefined ||
        hasForwardEvidence ||
        hasRecoveryEvidence)) ||
    (hasForwardEvidence && !hasCreated) ||
    (hasRecoveryEvidence && hasCreated) ||
    ((hasCreated || hasForwardEvidence) && !forwardOnlyPhase(result.phase)) ||
    (hasRecoveryEvidence &&
      (result.recovery_action === undefined ||
        !recoveryActionMatchesReportedPhase(
          result.recovery_action,
          result.phase,
          result.recovery_dispatch_state,
          result.recovery_failed_step
        ))) ||
    (result.recovery_action === "resume_forward_reconcile" &&
      (result.phase !== "ownership_published" || hasRecoveryEvidence)) ||
    (hasForwardEvidence &&
      result.recovery_action !== undefined &&
      (result.phase !== "ownership_published" ||
        result.recovery_action !== "resume_forward_reconcile"))
  ) {
    return null
  }

  const allDeleteTrace =
    result.delete_perform_started &&
    result.request_may_have_been_dispatched &&
    result.ndms_delete_dispatched
  const anyDeleteTrace =
    result.delete_perform_started ||
    result.request_may_have_been_dispatched ||
    result.ndms_delete_dispatched
  if (
    anyDeleteTrace !== allDeleteTrace ||
    (anyDeleteTrace && result.delete_transport_outcome === undefined)
  ) {
    return null
  }
  if (result.delete_transport_outcome !== undefined) {
    const knownZeroTrace =
      result.delete_transport_outcome === "guard_rejected" ||
      (result.delete_transport_outcome === "transport_failed" &&
        result.stop === "delete_guard_rejected")
    if (
      (knownZeroTrace ? anyDeleteTrace : !allDeleteTrace) ||
      !result.external_ndms_writer_race_accepted ||
      !destructiveRecoveryAction(result.recovery_action) ||
      result.recovery_admission_state !== "admitted" ||
      result.recovery_dispatch_state === undefined
    ) {
      return null
    }
  }
  const deleteCompletedBeforeFailure =
    destructiveRecoveryAction(result.recovery_action) &&
    (result.recovery_failed_step === "advance_wal_absence_verified" ||
      result.recovery_failed_step === "remove_wal_record")
  if (
    deleteCompletedBeforeFailure &&
    (!allDeleteTrace ||
      result.delete_transport_outcome === undefined ||
      result.delete_transport_outcome === "guard_rejected")
  ) {
    return null
  }

  if (
    result.rollback_snapshot_retired &&
    (!hasRecord ||
      !cleanupRecoveryAction(result.recovery_action) ||
      !hasRecoveryEvidence ||
      hasForwardEvidence ||
      result.ownership_published)
  ) {
    return null
  }
  if (
    result.wal_removed !== (result.status === "completed") ||
    (result.status === "recovery_required" &&
      result.rollback_snapshot_retired &&
      result.stop !== "wal_cleanup_failed" &&
      result.stop !== "unexpected_failure")
  ) {
    return null
  }

  const noRecordWorkEvidence =
    !hasCreated &&
    !result.ownership_published &&
    result.recovery_action === undefined &&
    !hasForwardEvidence &&
    !hasRecoveryEvidence &&
    result.delete_transport_outcome === undefined &&
    !anyDeleteTrace
  const exactForwardFailure = (step: (typeof importRecoverySteps)[number]) =>
    result.status === "blocked" &&
    hasRecord &&
    hasCreated &&
    result.forward_admission_state === "admitted" &&
    result.forward_dispatch_state === "step_failed" &&
    result.forward_failed_step === step &&
    result.direct_observation_failure === undefined
  const exactRecoveryFailure = (step: (typeof importRecoverySteps)[number]) =>
    result.status === "recovery_required" &&
    hasRecord &&
    result.recovery_action !== undefined &&
    result.recovery_admission_state === "admitted" &&
    result.recovery_dispatch_state === "step_failed" &&
    result.recovery_failed_step === step

  let stopCoherent = true
  switch (result.stop) {
    case "none":
    case "unexpected_failure":
      break
    case "writer_missing":
    case "writer_lost":
      stopCoherent =
        result.status === "blocked" &&
        result.delete_wal_readiness === undefined &&
        result.import_wal_readiness === undefined &&
        !hasRecord &&
        noRecordWorkEvidence &&
        result.direct_observation_failure === undefined
      break
    case "delete_wal_not_clean":
      stopCoherent =
        result.status === "blocked" &&
        result.delete_wal_readiness !== undefined &&
        result.delete_wal_readiness !== "clean" &&
        result.import_wal_readiness === undefined &&
        !hasRecord &&
        noRecordWorkEvidence
      break
    case "import_wal_not_single_safe":
      stopCoherent =
        result.status === "blocked" &&
        result.delete_wal_readiness === "clean" &&
        result.import_wal_readiness !== undefined &&
        result.import_wal_readiness !== "clean" &&
        !hasRecord &&
        noRecordWorkEvidence
      break
    case "record_not_cooperative":
    case "phase_not_forward_only":
    case "expected_target_not_managed":
      stopCoherent =
        result.status === "blocked" &&
        hasRecord &&
        noRecordWorkEvidence &&
        result.direct_observation_failure === undefined
      break
    case "first_observation_failed":
    case "second_observation_failed":
      stopCoherent =
        hasRecord &&
        result.direct_observation_failure !== undefined &&
        !hasCreated &&
        !hasForwardEvidence
      break
    case "observation_kind_mismatch":
    case "durable_observation_failed":
    case "observation_unstable":
      stopCoherent =
        hasRecord &&
        result.direct_observation_failure === undefined &&
        !hasCreated &&
        !hasForwardEvidence
      break
    case "ownership_not_exact":
      stopCoherent =
        hasRecord &&
        !hasCreated &&
        !hasForwardEvidence &&
        !result.ownership_published
      break
    case "snapshot_not_exact":
      stopCoherent =
        hasRecord &&
        result.recovery_action !== undefined &&
        !hasCreated &&
        !hasForwardEvidence &&
        !result.rollback_snapshot_retired
      break
    case "recovery_action_not_forward_only":
    case "recovery_action_not_actionable":
      stopCoherent =
        result.status === "blocked" &&
        hasRecord &&
        !hasCreated &&
        result.recovery_action !== undefined &&
        !hasForwardEvidence &&
        !hasRecoveryEvidence &&
        result.direct_observation_failure === undefined
      break
    case "external_writer_race_not_accepted":
      stopCoherent =
        result.status === "recovery_required" &&
        hasRecord &&
        destructiveRecoveryAction(result.recovery_action) &&
        !result.external_ndms_writer_race_accepted &&
        !hasForwardEvidence &&
        !hasRecoveryEvidence &&
        result.delete_transport_outcome === undefined
      break
    case "forward_admission_failed":
      stopCoherent =
        result.status === "blocked" &&
        hasRecord &&
        hasCreated &&
        result.forward_admission_state !== undefined &&
        result.forward_admission_state !== "admitted" &&
        result.forward_dispatch_state === undefined &&
        result.forward_failed_step === undefined &&
        !hasRecoveryEvidence
      break
    case "recovery_admission_failed":
      stopCoherent =
        result.status === "recovery_required" &&
        hasRecord &&
        result.recovery_action !== undefined &&
        result.recovery_admission_state !== undefined &&
        result.recovery_admission_state !== "admitted" &&
        result.recovery_dispatch_state === undefined &&
        result.recovery_failed_step === undefined &&
        result.delete_transport_outcome === undefined
      break
    case "target_verified_wal_publish_failed":
      stopCoherent = exactForwardFailure("advance_wal_target_verified")
      break
    case "ownership_publish_failed":
      stopCoherent = exactForwardFailure("publish_ownership")
      break
    case "ownership_wal_publish_failed":
      stopCoherent = exactForwardFailure("advance_wal_ownership_published")
      break
    case "rollback_wal_publish_failed":
      stopCoherent = exactRecoveryFailure("advance_wal_rollback_requested")
      break
    case "ownership_retract_failed":
      stopCoherent = exactRecoveryFailure("remove_ownership_claim")
      break
    case "delete_wal_publish_failed":
      stopCoherent = exactRecoveryFailure("advance_wal_delete_may_be_inflight")
      break
    case "delete_guard_rejected":
      stopCoherent =
        exactRecoveryFailure("delete_exact_owned_target") &&
        (result.delete_transport_outcome === "guard_rejected" ||
          result.delete_transport_outcome === "transport_failed") &&
        !anyDeleteTrace
      break
    case "delete_transport_ambiguous":
      stopCoherent =
        exactRecoveryFailure("delete_exact_owned_target") &&
        result.delete_transport_outcome !== undefined &&
        result.delete_transport_outcome !== "guard_rejected" &&
        allDeleteTrace
      break
    case "absence_wal_publish_failed":
      stopCoherent = exactRecoveryFailure("advance_wal_absence_verified")
      break
    case "snapshot_retirement_failed":
      stopCoherent =
        exactRecoveryFailure("remove_wal_record") &&
        !result.rollback_snapshot_retired
      break
    case "wal_cleanup_failed":
      stopCoherent =
        exactForwardFailure("remove_wal_record") ||
        (exactRecoveryFailure("remove_wal_record") &&
          result.rollback_snapshot_retired)
      break
  }
  if (!stopCoherent) return null

  if (
    result.status === "no_work" &&
    (result.stop !== "none" ||
      hasRecord ||
      hasCreated ||
      result.delete_wal_readiness !== "clean" ||
      result.import_wal_readiness !== "clean" ||
      result.wal_may_require_recovery ||
      result.ownership_published ||
      result.rollback_snapshot_retired ||
      result.wal_removed ||
      result.direct_observation_failure !== undefined ||
      result.recovery_action !== undefined ||
      hasForwardEvidence ||
      hasRecoveryEvidence ||
      result.delete_transport_outcome !== undefined ||
      anyDeleteTrace)
  ) {
    return null
  }
  if (
    result.status === "blocked" &&
    (result.stop === "none" ||
      result.wal_removed ||
      result.rollback_snapshot_retired ||
      anyDeleteTrace ||
      result.delete_transport_outcome !== undefined ||
      hasRecoveryEvidence ||
      result.forward_dispatch_state === "completed")
  ) {
    return null
  }
  if (
    result.status === "recovery_required" &&
    (result.stop === "none" ||
      !hasRecord ||
      !result.wal_may_require_recovery ||
      result.wal_removed)
  ) {
    return null
  }
  if (
    result.status === "completed" &&
    (result.stop !== "none" ||
      !hasRecord ||
      result.wal_may_require_recovery ||
      !result.wal_removed ||
      result.direct_observation_failure !== undefined ||
      hasCreated === result.rollback_snapshot_retired)
  ) {
    return null
  }
  if (result.status === "completed" && hasCreated) {
    const ownershipReconcile = result.phase === "ownership_published"
    if (
      !forwardOnlyPhase(result.phase) ||
      !result.ownership_published ||
      hasRecoveryEvidence ||
      result.delete_transport_outcome !== undefined ||
      anyDeleteTrace ||
      result.forward_admission_state !== "admitted" ||
      result.forward_dispatch_state !== "completed" ||
      result.forward_failed_step !== undefined ||
      (ownershipReconcile
        ? result.recovery_action !== "resume_forward_reconcile"
        : result.recovery_action !== undefined)
    ) {
      return null
    }
  }
  if (result.status === "completed" && !hasCreated) {
    if (
      result.ownership_published ||
      hasForwardEvidence ||
      !result.rollback_snapshot_retired ||
      !cleanupRecoveryAction(result.recovery_action) ||
      result.recovery_admission_state !== "admitted" ||
      result.recovery_dispatch_state !== "completed" ||
      result.recovery_failed_step !== undefined ||
      destructiveRecoveryAction(result.recovery_action) !== anyDeleteTrace ||
      (destructiveRecoveryAction(result.recovery_action) &&
        (!result.external_ndms_writer_race_accepted ||
          result.delete_transport_outcome === undefined))
    ) {
      return null
    }
  }
  return result
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

export async function postNdmsNativeTombstoneForgetOnce(
  request: NdmsNativeTombstoneForgetRequest,
  fetchImpl: typeof fetch = fetch
): Promise<NdmsNativeTombstoneForgetResult> {
  if (
    !validFirmwareInterface(request.interface_name) ||
    request.confirm_interface_name !== request.interface_name ||
    !validTombstoneOwnershipRevision(request.expected_ownership_revision) ||
    request.rollback_discard_acknowledgement !==
      "permanently_discard_rollback_data" ||
    request.foreign_reappearance_acknowledgement !==
      "accepted_reappearance_is_foreign"
  ) {
    throw new NativeMutationTransportError("rejected")
  }
  const response = await fetchWithStepUp(
    NDMS_NATIVE_TOMBSTONE_FORGET_PATH,
    {
      ...commonRequestInit,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    },
    fetchImpl
  )
  const result = await parseTrustedResponse(
    response,
    parseNdmsNativeTombstoneForgetResult
  )
  if (result.interface_name !== request.interface_name) {
    throw new NativeMutationTransportError("outcome_unknown")
  }
  return result
}

export async function postNdmsNativeImportRecoveryOnce(
  acceptanceOrFetch: boolean | typeof fetch = false,
  fetchImpl: typeof fetch = fetch
): Promise<NdmsNativeImportRecoveryResult> {
  const acceptance =
    typeof acceptanceOrFetch === "boolean" ? acceptanceOrFetch : false
  const requestFetch =
    typeof acceptanceOrFetch === "boolean" ? fetchImpl : acceptanceOrFetch
  const response = await fetchWithStepUp(
    NDMS_NATIVE_IMPORT_RECOVERY_PATH,
    {
      ...commonRequestInit,
      ...(acceptance
        ? {
            headers: {
              "X-Keen-Pbr-External-Ndms-Writer-Race-Acceptance":
                "owner-accepted",
            },
          }
        : {}),
    },
    requestFetch
  )
  const result = await parseTrustedResponse(
    response,
    parseNdmsNativeImportRecoveryResult
  )
  if (result.external_ndms_writer_race_accepted !== acceptance) {
    throw new NativeMutationTransportError("outcome_unknown")
  }
  return result
}

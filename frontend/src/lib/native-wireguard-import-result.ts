export const NDMS_NATIVE_IMPORT_STATUSES = [
  "blocked",
  "recovery_required",
  "completed",
] as const

export const NDMS_NATIVE_IMPORT_STOPS = [
  "none",
  "external_writer_race_not_accepted",
  "writer_missing",
  "writer_lost",
  "delete_wal_not_clean",
  "import_wal_not_clean",
  "request_invalid",
  "runtime_catalog_failed",
  "running_config_catalog_failed",
  "prewrite_catalog_unsafe",
  "prewrite_catalog_diverged",
  "marker_collision",
  "first_free_target_not_managed",
  "ownership_target_not_available",
  "snapshot_target_not_available",
  "durable_observation_failed",
  "cooperative_baseline_failed",
  "cooperative_writer_admission_failed",
  "executor_blocked",
  "wal_record_unavailable",
  "first_post_observation_failed",
  "second_post_observation_failed",
  "post_observation_kind_mismatch",
  "post_observation_unstable",
  "forward_completion_blocked",
  "forward_admission_failed",
  "target_verified_wal_publish_failed",
  "ownership_publish_failed",
  "ownership_wal_publish_failed",
  "wal_cleanup_failed",
  "unexpected_failure",
] as const

const requestErrors = [
  "input_too_large",
  "invalid_encoding",
  "unsupported_uri",
  "invalid_base64",
  "invalid_compression",
  "invalid_json",
  "unsupported_json_schema",
  "malformed_line",
  "unknown_section",
  "duplicate_section",
  "duplicate_field",
  "duplicate_peer",
  "unknown_field",
  "dangerous_directive",
  "missing_required_field",
  "invalid_field",
  "limit_exceeded",
] as const

const walReadiness = ["clean", "unfinished", "unsafe"] as const
const importKinds = ["wireguard", "amnezia_wireguard"] as const
const directObservationFailures = [
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
const baselineErrors = [
  "firmware_unavailable",
  "catalog_not_fresh",
  "catalog_not_refreshed",
  "catalog_observation_missing",
  "observation_generation_invalid",
  "observation_epoch_mismatch",
  "slot_evidence_incomplete",
  "slot_evidence_invalid",
  "expected_target_invalid",
  "allocator_namespace_full",
  "first_free_target_protected",
  "expected_target_occupied",
  "expected_target_not_first_free",
  "maintenance_generation_exhausted",
  "allocator_generation_invalid",
  "durable_observation_invalid",
  "durable_observation_mismatch",
] as const
const executorStops = [
  "none",
  "missing_dependency",
  "request_identity_invalid",
  "snapshot_identity_invalid",
  "observation_binding_invalid",
  "expected_target_ineligible",
  "baseline_mismatch",
  "incompatible_fence_mode",
  "fence_required",
  "authority_conflict",
  "cooperative_writer_required",
  "cooperative_writer_invalid",
  "cooperative_writer_lost",
  "cooperative_observation_changed",
  "request_binding_failed",
  "generation_observation_failed",
  "fence_invalid",
  "unfinished_transaction_present",
  "prepared_wal_publish_failed",
  "snapshot_publish_failed",
  "generation_reservation_failed",
  "generation_changed",
  "inflight_wal_publish_failed",
  "fence_lost_after_intent",
  "transport_failed",
  "response_wal_publish_failed",
  "ambiguous_response",
] as const
const forwardAdmissionStates = [
  "admitted",
  "lease_busy",
  "lease_io_error",
  "inventory_not_ready",
  "record_missing",
  "record_changed",
  "action_not_actionable",
] as const
const forwardDispatchStates = [
  "completed",
  "lease_not_held",
  "plan_empty",
  "target_missing",
  "target_not_eligible",
  "ownership_store_missing",
  "snapshot_retirer_missing",
  "step_failed",
] as const
const forwardSteps = [
  "advance_wal_target_verified",
  "publish_ownership",
  "advance_wal_ownership_published",
  "remove_wal_record",
] as const

export type NdmsNativeImportStatus =
  (typeof NDMS_NATIVE_IMPORT_STATUSES)[number]
export type NdmsNativeImportStop = (typeof NDMS_NATIVE_IMPORT_STOPS)[number]
export type NdmsNativeImportOutcome =
  "blocked" | "recovery_required" | "completed"

export type NdmsNativeImportClientResult = Readonly<{
  status: NdmsNativeImportStatus
  stop: NdmsNativeImportStop
  external_ndms_writer_race_excluded: false
  external_ndms_writer_race_accepted: boolean
  system_configuration_save_performed: boolean
  request_may_have_been_dispatched: boolean
  wal_may_require_recovery: boolean
  rollback_snapshot_may_be_retained: boolean
  ownership_published: boolean
  expected_interface?: string
  created_interface?: string
  created_kernel_interface?: string
  kind?: (typeof importKinds)[number]
  delete_wal_readiness?: (typeof walReadiness)[number]
  import_wal_readiness?: (typeof walReadiness)[number]
  request_error?: (typeof requestErrors)[number]
  direct_observation_failure?: (typeof directObservationFailures)[number]
  baseline_error?: (typeof baselineErrors)[number]
  executor_stop?: (typeof executorStops)[number]
  forward_admission_state?: (typeof forwardAdmissionStates)[number]
  forward_dispatch_state?: (typeof forwardDispatchStates)[number]
  forward_failed_step?: (typeof forwardSteps)[number]
}>

export type ProvedNativeImportIdentity = Readonly<{
  firmwareInterface: string
  kernelInterface: string
  kind: (typeof importKinds)[number]
}>

const allowedKeys = new Set([
  "status",
  "stop",
  "external_ndms_writer_race_excluded",
  "external_ndms_writer_race_accepted",
  "system_configuration_save_performed",
  "request_may_have_been_dispatched",
  "wal_may_require_recovery",
  "rollback_snapshot_may_be_retained",
  "ownership_published",
  "expected_interface",
  "created_interface",
  "created_kernel_interface",
  "kind",
  "delete_wal_readiness",
  "import_wal_readiness",
  "request_error",
  "direct_observation_failure",
  "baseline_error",
  "executor_stop",
  "forward_admission_state",
  "forward_dispatch_state",
  "forward_failed_step",
])

const blockedStops = [
  "external_writer_race_not_accepted",
  "writer_missing",
  "writer_lost",
  "delete_wal_not_clean",
  "import_wal_not_clean",
  "request_invalid",
  "runtime_catalog_failed",
  "running_config_catalog_failed",
  "prewrite_catalog_unsafe",
  "prewrite_catalog_diverged",
  "marker_collision",
  "first_free_target_not_managed",
  "ownership_target_not_available",
  "snapshot_target_not_available",
  "durable_observation_failed",
  "cooperative_baseline_failed",
  "cooperative_writer_admission_failed",
  "executor_blocked",
  "unexpected_failure",
] as const

const recoveryStops = [
  "executor_blocked",
  "wal_record_unavailable",
  "first_post_observation_failed",
  "second_post_observation_failed",
  "post_observation_kind_mismatch",
  "post_observation_unstable",
  "forward_completion_blocked",
  "forward_admission_failed",
  "target_verified_wal_publish_failed",
  "ownership_publish_failed",
  "ownership_wal_publish_failed",
  "wal_cleanup_failed",
  "unexpected_failure",
] as const

const blockedExecutorStops = [
  "missing_dependency",
  "request_identity_invalid",
  "snapshot_identity_invalid",
  "observation_binding_invalid",
  "expected_target_ineligible",
  "baseline_mismatch",
  "incompatible_fence_mode",
  "authority_conflict",
  "cooperative_writer_required",
  "cooperative_writer_invalid",
  "cooperative_writer_lost",
  "cooperative_observation_changed",
  "request_binding_failed",
  "generation_observation_failed",
] as const

const recoveryExecutorStops = [
  "cooperative_writer_lost",
  "cooperative_observation_changed",
  "generation_observation_failed",
  "prepared_wal_publish_failed",
  "snapshot_publish_failed",
  "generation_reservation_failed",
  "generation_changed",
  "inflight_wal_publish_failed",
  "transport_failed",
  "response_wal_publish_failed",
  "ambiguous_response",
] as const

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

/**
 * Copies only the public, bounded response contract into UI state. Unknown
 * keys or incoherent success claims turn into an opaque unknown outcome, so a
 * faulty response can neither leak text into the page nor enable a retry.
 */
export function parseNdmsNativeImportResult(
  payload: unknown
): NdmsNativeImportClientResult | null {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return null
  }
  const value = payload as Record<string, unknown>
  if (Object.keys(value).some((key) => !allowedKeys.has(key))) return null
  if (
    !inList(value.status, NDMS_NATIVE_IMPORT_STATUSES) ||
    !inList(value.stop, NDMS_NATIVE_IMPORT_STOPS) ||
    value.external_ndms_writer_race_excluded !== false ||
    typeof value.external_ndms_writer_race_accepted !== "boolean" ||
    typeof value.system_configuration_save_performed !== "boolean" ||
    typeof value.request_may_have_been_dispatched !== "boolean" ||
    typeof value.wal_may_require_recovery !== "boolean" ||
    typeof value.rollback_snapshot_may_be_retained !== "boolean" ||
    typeof value.ownership_published !== "boolean" ||
    (value.expected_interface !== undefined &&
      !validFirmwareInterface(value.expected_interface)) ||
    (value.kind !== undefined && !inList(value.kind, importKinds)) ||
    (value.delete_wal_readiness !== undefined &&
      !inList(value.delete_wal_readiness, walReadiness)) ||
    (value.import_wal_readiness !== undefined &&
      !inList(value.import_wal_readiness, walReadiness)) ||
    (value.request_error !== undefined &&
      !inList(value.request_error, requestErrors)) ||
    (value.direct_observation_failure !== undefined &&
      !inList(value.direct_observation_failure, directObservationFailures)) ||
    (value.baseline_error !== undefined &&
      !inList(value.baseline_error, baselineErrors)) ||
    (value.executor_stop !== undefined &&
      !inList(value.executor_stop, executorStops)) ||
    (value.forward_admission_state !== undefined &&
      !inList(value.forward_admission_state, forwardAdmissionStates)) ||
    (value.forward_dispatch_state !== undefined &&
      !inList(value.forward_dispatch_state, forwardDispatchStates)) ||
    (value.forward_failed_step !== undefined &&
      !inList(value.forward_failed_step, forwardSteps))
  ) {
    return null
  }

  const createdPairPresent =
    value.created_interface !== undefined ||
    value.created_kernel_interface !== undefined
  const kindPresent = value.kind !== undefined
  const expectedPresent = value.expected_interface !== undefined
  if (
    (expectedPresent && !kindPresent) ||
    (createdPairPresent &&
      (!validFirmwareInterface(value.created_interface) ||
        !validKernelInterface(value.created_kernel_interface) ||
        !expectedPresent ||
        !kindPresent ||
        value.created_interface !== value.expected_interface))
  ) {
    return null
  }

  const hasForwardEvidence =
    value.forward_admission_state !== undefined ||
    value.forward_dispatch_state !== undefined ||
    value.forward_failed_step !== undefined
  const dispatchStepFailed = value.forward_dispatch_state === "step_failed"
  if (
    (value.ownership_published && !createdPairPresent) ||
    (hasForwardEvidence && !createdPairPresent) ||
    (createdPairPresent &&
      (!value.request_may_have_been_dispatched ||
        !value.rollback_snapshot_may_be_retained)) ||
    (value.request_may_have_been_dispatched &&
      !value.rollback_snapshot_may_be_retained) ||
    (value.forward_dispatch_state !== undefined &&
      value.forward_admission_state !== "admitted") ||
    (value.forward_failed_step !== undefined) !== dispatchStepFailed ||
    (value.forward_dispatch_state === "completed" &&
      value.status !== "completed")
  ) {
    return null
  }

  const catalogObservationStop =
    value.stop === "runtime_catalog_failed" ||
    value.stop === "running_config_catalog_failed"
  const postObservationStop =
    value.stop === "first_post_observation_failed" ||
    value.stop === "second_post_observation_failed"
  if (
    (value.request_error !== undefined) !==
      (value.stop === "request_invalid") ||
    (value.direct_observation_failure !== undefined &&
      !catalogObservationStop &&
      !postObservationStop) ||
    (catalogObservationStop &&
      value.direct_observation_failure === undefined) ||
    (value.baseline_error !== undefined) !==
      (value.stop === "cooperative_baseline_failed")
  ) {
    return null
  }

  const noAdmissionEvidence =
    value.delete_wal_readiness === undefined &&
    value.import_wal_readiness === undefined
  const cleanAdmissionEvidence =
    value.delete_wal_readiness === "clean" &&
    value.import_wal_readiness === "clean"
  const noPublicIdentity = !kindPresent && !expectedPresent
  const requestIdentityOnly = kindPresent && !expectedPresent
  const fullPublicIdentity = kindPresent && expectedPresent
  const noCreatedOrForwardEvidence =
    !createdPairPresent && !value.ownership_published && !hasForwardEvidence

  if (
    value.system_configuration_save_performed !==
    (value.status === "completed")
  ) {
    return null
  }

  if (value.status === "blocked") {
    const consentRefused = value.stop === "external_writer_race_not_accepted"
    let exactStopEvidence = false
    switch (value.stop) {
      case "external_writer_race_not_accepted":
      case "writer_missing":
        exactStopEvidence = noPublicIdentity && noAdmissionEvidence
        break
      case "writer_lost":
        exactStopEvidence =
          (noPublicIdentity && noAdmissionEvidence) ||
          (fullPublicIdentity && cleanAdmissionEvidence)
        break
      case "delete_wal_not_clean":
        exactStopEvidence =
          noPublicIdentity &&
          value.delete_wal_readiness !== undefined &&
          value.delete_wal_readiness !== "clean" &&
          value.import_wal_readiness === undefined
        break
      case "import_wal_not_clean":
        exactStopEvidence =
          noPublicIdentity &&
          value.delete_wal_readiness === "clean" &&
          value.import_wal_readiness !== undefined &&
          value.import_wal_readiness !== "clean"
        break
      case "request_invalid":
        exactStopEvidence = noPublicIdentity && cleanAdmissionEvidence
        break
      case "runtime_catalog_failed":
      case "running_config_catalog_failed":
      case "prewrite_catalog_unsafe":
      case "prewrite_catalog_diverged":
      case "marker_collision":
      case "first_free_target_not_managed":
        exactStopEvidence = requestIdentityOnly && cleanAdmissionEvidence
        break
      case "ownership_target_not_available":
      case "snapshot_target_not_available":
      case "durable_observation_failed":
      case "cooperative_baseline_failed":
      case "cooperative_writer_admission_failed":
      case "executor_blocked":
        exactStopEvidence = fullPublicIdentity && cleanAdmissionEvidence
        break
      case "unexpected_failure":
        exactStopEvidence =
          (noPublicIdentity && noAdmissionEvidence) ||
          ((requestIdentityOnly || fullPublicIdentity) &&
            cleanAdmissionEvidence)
        break
    }
    if (
      !inList(value.stop, blockedStops) ||
      !exactStopEvidence ||
      value.external_ndms_writer_race_accepted === consentRefused ||
      value.wal_may_require_recovery ||
      value.request_may_have_been_dispatched ||
      value.rollback_snapshot_may_be_retained ||
      !noCreatedOrForwardEvidence ||
      (value.executor_stop !== undefined) !==
        (value.stop === "executor_blocked") ||
      (value.executor_stop !== undefined &&
        !inList(value.executor_stop, blockedExecutorStops))
    ) {
      return null
    }
  }

  if (value.status === "recovery_required") {
    const executorBlocked = value.stop === "executor_blocked"
    const executorRecoveryStop = inList(
      value.executor_stop,
      recoveryExecutorStops
    )
    const snapshotMayBeAbsent =
      executorBlocked &&
      (value.executor_stop === "prepared_wal_publish_failed" ||
        value.executor_stop === "cooperative_writer_lost" ||
        value.executor_stop === "cooperative_observation_changed")
    if (
      !inList(value.stop, recoveryStops) ||
      value.external_ndms_writer_race_accepted !== true ||
      value.wal_may_require_recovery !== true ||
      !fullPublicIdentity ||
      !cleanAdmissionEvidence ||
      executorBlocked !== executorRecoveryStop ||
      (!executorBlocked && value.executor_stop !== "none") ||
      (!value.rollback_snapshot_may_be_retained && !snapshotMayBeAbsent) ||
      (value.executor_stop === "prepared_wal_publish_failed" &&
        value.rollback_snapshot_may_be_retained) ||
      (!executorBlocked && !value.request_may_have_been_dispatched) ||
      value.request_error !== undefined ||
      value.baseline_error !== undefined
    ) {
      return null
    }

    const exactDispatchFailure = (step: (typeof forwardSteps)[number]) =>
      createdPairPresent &&
      value.forward_admission_state === "admitted" &&
      value.forward_dispatch_state === "step_failed" &&
      value.forward_failed_step === step

    switch (value.stop) {
      case "executor_blocked":
      case "wal_record_unavailable":
      case "first_post_observation_failed":
      case "second_post_observation_failed":
      case "post_observation_kind_mismatch":
      case "post_observation_unstable":
        if (!noCreatedOrForwardEvidence) return null
        break
      case "forward_completion_blocked":
        if (
          value.ownership_published ||
          (createdPairPresent &&
            (value.forward_admission_state !== "admitted" ||
              value.forward_dispatch_state !== undefined ||
              value.forward_failed_step !== undefined)) ||
          (!createdPairPresent && hasForwardEvidence)
        ) {
          return null
        }
        break
      case "forward_admission_failed":
        if (
          !createdPairPresent ||
          value.forward_admission_state === undefined ||
          value.forward_admission_state === "admitted" ||
          value.forward_dispatch_state !== undefined ||
          value.forward_failed_step !== undefined ||
          value.ownership_published
        ) {
          return null
        }
        break
      case "target_verified_wal_publish_failed":
        if (
          !exactDispatchFailure("advance_wal_target_verified") ||
          value.ownership_published
        ) {
          return null
        }
        break
      case "ownership_publish_failed":
        if (!exactDispatchFailure("publish_ownership")) return null
        break
      case "ownership_wal_publish_failed":
        if (!exactDispatchFailure("advance_wal_ownership_published")) {
          return null
        }
        break
      case "wal_cleanup_failed":
        if (!exactDispatchFailure("remove_wal_record")) return null
        break
      case "unexpected_failure":
        break
    }
  }

  if (
    value.status === "completed" &&
    (value.stop !== "none" ||
      !validFirmwareInterface(value.expected_interface) ||
      !validFirmwareInterface(value.created_interface) ||
      !validKernelInterface(value.created_kernel_interface) ||
      value.expected_interface !== value.created_interface ||
      !inList(value.kind, importKinds) ||
      value.delete_wal_readiness !== "clean" ||
      value.import_wal_readiness !== "clean" ||
      value.request_may_have_been_dispatched !== true ||
      value.ownership_published !== true ||
      value.external_ndms_writer_race_accepted !== true ||
      value.wal_may_require_recovery !== false ||
      value.rollback_snapshot_may_be_retained !== true ||
      value.request_error !== undefined ||
      value.direct_observation_failure !== undefined ||
      value.baseline_error !== undefined ||
      value.executor_stop !== "none" ||
      value.forward_admission_state !== "admitted" ||
      value.forward_dispatch_state !== "completed" ||
      value.forward_failed_step !== undefined)
  ) {
    return null
  }

  return value as NdmsNativeImportClientResult
}

export function ndmsNativeImportOutcome(
  result: NdmsNativeImportClientResult
): NdmsNativeImportOutcome {
  if (result.status === "completed") return "completed"
  if (
    result.status === "recovery_required" ||
    result.wal_may_require_recovery ||
    (result.delete_wal_readiness !== undefined &&
      result.delete_wal_readiness !== "clean") ||
    (result.import_wal_readiness !== undefined &&
      result.import_wal_readiness !== "clean")
  ) {
    return "recovery_required"
  }
  return "blocked"
}

export function provedCompletedNativeImportIdentity(
  result: NdmsNativeImportClientResult
): ProvedNativeImportIdentity | null {
  if (
    result.status !== "completed" ||
    !result.created_interface ||
    !result.created_kernel_interface ||
    !result.kind
  ) {
    return null
  }
  return {
    firmwareInterface: result.created_interface,
    kernelInterface: result.created_kernel_interface,
    kind: result.kind,
  }
}

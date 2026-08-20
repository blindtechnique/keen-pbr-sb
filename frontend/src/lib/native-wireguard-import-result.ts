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

export type NdmsNativeImportStatus =
  (typeof NDMS_NATIVE_IMPORT_STATUSES)[number]
export type NdmsNativeImportStop = (typeof NDMS_NATIVE_IMPORT_STOPS)[number]
export type NdmsNativeImportOutcome =
  | "blocked"
  | "recovery_required"
  | "completed"

export type NdmsNativeImportClientResult = Readonly<{
  status: NdmsNativeImportStatus
  stop: NdmsNativeImportStop
  external_ndms_writer_race_excluded: false
  external_ndms_writer_race_accepted: boolean
  system_configuration_save_performed: false
  request_may_have_been_dispatched: boolean
  wal_may_require_recovery: boolean
  rollback_snapshot_may_be_retained: boolean
  ownership_published: boolean
  transaction_id?: string
  expected_interface?: string
  created_interface?: string
  created_kernel_interface?: string
  kind?: (typeof importKinds)[number]
  delete_wal_readiness?: (typeof walReadiness)[number]
  import_wal_readiness?: (typeof walReadiness)[number]
  request_error?: (typeof requestErrors)[number]
  direct_observation_failure?: string
  baseline_error?: string
  executor_stop?: string
  forward_admission_state?: string
  forward_dispatch_state?: string
  forward_failed_step?: string
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
  "transaction_id",
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

const inList = <T extends string>(
  value: unknown,
  values: readonly T[]
): value is T => typeof value === "string" && values.includes(value as T)

const optionalBoundedString = (value: unknown): value is string | undefined =>
  value === undefined || (typeof value === "string" && value.length <= 96)

const validFirmwareInterface = (value: unknown): value is string =>
  typeof value === "string" &&
  /^Wireguard(?:[0-9]|[1-9][0-9]|1[01][0-9]|12[0-6])$/.test(value)

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
    value.system_configuration_save_performed !== false ||
    typeof value.request_may_have_been_dispatched !== "boolean" ||
    typeof value.wal_may_require_recovery !== "boolean" ||
    typeof value.rollback_snapshot_may_be_retained !== "boolean" ||
    typeof value.ownership_published !== "boolean" ||
    (value.transaction_id !== undefined &&
      (typeof value.transaction_id !== "string" ||
        !/^[0-9a-f]{32}$/.test(value.transaction_id))) ||
    (value.expected_interface !== undefined &&
      !validFirmwareInterface(value.expected_interface)) ||
    (value.kind !== undefined && !inList(value.kind, importKinds)) ||
    (value.delete_wal_readiness !== undefined &&
      !inList(value.delete_wal_readiness, walReadiness)) ||
    (value.import_wal_readiness !== undefined &&
      !inList(value.import_wal_readiness, walReadiness)) ||
    (value.request_error !== undefined &&
      !inList(value.request_error, requestErrors)) ||
    !optionalBoundedString(value.direct_observation_failure) ||
    !optionalBoundedString(value.baseline_error) ||
    !optionalBoundedString(value.executor_stop) ||
    !optionalBoundedString(value.forward_admission_state) ||
    !optionalBoundedString(value.forward_dispatch_state) ||
    !optionalBoundedString(value.forward_failed_step)
  ) {
    return null
  }

  const createdPairPresent =
    value.created_interface !== undefined ||
    value.created_kernel_interface !== undefined
  if (
    createdPairPresent &&
    (!validFirmwareInterface(value.created_interface) ||
      !validKernelInterface(value.created_kernel_interface))
  ) {
    return null
  }

  const nonCleanWal =
    (value.delete_wal_readiness !== undefined &&
      value.delete_wal_readiness !== "clean") ||
    (value.import_wal_readiness !== undefined &&
      value.import_wal_readiness !== "clean")
  const recoverySignal = value.wal_may_require_recovery || nonCleanWal

  if (value.status === "blocked") {
    if (
      value.stop === "none" ||
      value.external_ndms_writer_race_accepted !== true
    ) {
      return null
    }
    // A retryable block is proved safe only before dispatch and before any
    // durable mutation artifact or created identity exists. Explicit dirty WAL
    // evidence is accepted only as a recovery-locked outcome below.
    if (
      !recoverySignal &&
      (value.request_may_have_been_dispatched ||
        value.rollback_snapshot_may_be_retained ||
        value.ownership_published ||
        createdPairPresent)
    ) {
      return null
    }
  }

  if (
    value.status === "recovery_required" &&
    (value.stop === "none" ||
      value.external_ndms_writer_race_accepted !== true ||
      !recoverySignal)
  ) {
    return null
  }

  if (
    value.status === "completed" &&
    (value.stop !== "none" ||
      typeof value.transaction_id !== "string" ||
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
      value.rollback_snapshot_may_be_retained !== true)
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

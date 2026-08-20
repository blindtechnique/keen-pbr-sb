import { describe, expect, test } from "bun:test"

import {
  ndmsNativeImportOutcome,
  parseNdmsNativeImportResult,
  provedCompletedNativeImportIdentity,
} from "@/lib/native-wireguard-import-result"

const completed = () => ({
  status: "completed",
  stop: "none",
  external_ndms_writer_race_excluded: false,
  external_ndms_writer_race_accepted: true,
  system_configuration_save_performed: false,
  request_may_have_been_dispatched: true,
  wal_may_require_recovery: false,
  rollback_snapshot_may_be_retained: true,
  ownership_published: true,
  expected_interface: "Wireguard5",
  created_interface: "Wireguard5",
  created_kernel_interface: "nwg5",
  kind: "wireguard",
  delete_wal_readiness: "clean",
  import_wal_readiness: "clean",
  executor_stop: "none",
  forward_admission_state: "admitted",
  forward_dispatch_state: "completed",
})

describe("native WireGuard import public result", () => {
  test("accepts only a coherent proved completed identity", () => {
    const result = parseNdmsNativeImportResult(completed())

    expect(result).not.toBeNull()
    expect(result && ndmsNativeImportOutcome(result)).toBe("completed")
    expect(result?.created_interface).toBe("Wireguard5")
    expect(result?.created_kernel_interface).toBe("nwg5")
    expect(result?.system_configuration_save_performed).toBe(false)
    expect(result && provedCompletedNativeImportIdentity(result)).toEqual({
      firmwareInterface: "Wireguard5",
      kernelInterface: "nwg5",
      kind: "wireguard",
    })
  })

  test("rejects every capability overclaim or incomplete completed shape", () => {
    for (const patch of [
      { external_ndms_writer_race_excluded: true },
      { system_configuration_save_performed: true },
      { external_ndms_writer_race_accepted: false },
      { request_may_have_been_dispatched: false },
      { ownership_published: false },
      { wal_may_require_recovery: true },
      { rollback_snapshot_may_be_retained: false },
      { stop: "executor_blocked" },
      { expected_interface: "Wireguard6" },
      {
        expected_interface: "Wireguard4",
        created_interface: "Wireguard4",
      },
      {
        expected_interface: "Wireguard99",
        created_interface: "Wireguard99",
      },
      { created_interface: undefined },
      { created_kernel_interface: undefined },
      { created_kernel_interface: "nwg5/private" },
      { transaction_id: "0123456789abcdef0123456789abcdef" },
      { kind: undefined },
      { delete_wal_readiness: "unfinished" },
      { import_wal_readiness: "unsafe" },
      { executor_stop: undefined },
      { executor_stop: "transport_failed" },
      { forward_admission_state: undefined },
      { forward_admission_state: "lease_busy" },
      { forward_dispatch_state: undefined },
      {
        forward_dispatch_state: "step_failed",
        forward_failed_step: "publish_ownership",
      },
      { request_error: "invalid_encoding" },
      { direct_observation_failure: "transport_failed" },
      { baseline_error: "catalog_not_fresh" },
    ]) {
      expect(
        parseNdmsNativeImportResult({ ...completed(), ...patch })
      ).toBeNull()
    }
  })

  test("classifies a typed recovery result as a no-retry outcome", () => {
    const result = parseNdmsNativeImportResult({
      ...completed(),
      status: "recovery_required",
      stop: "forward_completion_blocked",
      wal_may_require_recovery: true,
      ownership_published: false,
      created_interface: undefined,
      created_kernel_interface: undefined,
      forward_admission_state: undefined,
      forward_dispatch_state: undefined,
    })

    expect(result).not.toBeNull()
    expect(result && ndmsNativeImportOutcome(result)).toBe("recovery_required")
  })

  test("binds executor recovery to the truthful snapshot boundary", () => {
    const recovery = {
      ...completed(),
      status: "recovery_required",
      stop: "executor_blocked",
      request_may_have_been_dispatched: false,
      wal_may_require_recovery: true,
      rollback_snapshot_may_be_retained: false,
      ownership_published: false,
      created_interface: undefined,
      created_kernel_interface: undefined,
      executor_stop: "prepared_wal_publish_failed",
      forward_admission_state: undefined,
      forward_dispatch_state: undefined,
    }

    const result = parseNdmsNativeImportResult(recovery)
    expect(result && ndmsNativeImportOutcome(result)).toBe("recovery_required")
    expect(
      parseNdmsNativeImportResult({
        ...recovery,
        rollback_snapshot_may_be_retained: true,
      })
    ).toBeNull()
    expect(
      parseNdmsNativeImportResult({
        ...recovery,
        executor_stop: "snapshot_publish_failed",
      })
    ).toBeNull()
    expect(
      parseNdmsNativeImportResult({
        ...recovery,
        executor_stop: "snapshot_publish_failed",
        rollback_snapshot_may_be_retained: true,
      })
    ).not.toBeNull()
    expect(
      parseNdmsNativeImportResult({
        ...recovery,
        executor_stop: "unfinished_transaction_present",
      })
    ).toBeNull()
  })

  test("accepts a safe pre-dispatch block without inventing an interface", () => {
    const result = parseNdmsNativeImportResult({
      status: "blocked",
      stop: "writer_missing",
      external_ndms_writer_race_excluded: false,
      external_ndms_writer_race_accepted: true,
      system_configuration_save_performed: false,
      request_may_have_been_dispatched: false,
      wal_may_require_recovery: false,
      rollback_snapshot_may_be_retained: false,
      ownership_published: false,
    })

    expect(result).not.toBeNull()
    expect(result && ndmsNativeImportOutcome(result)).toBe("blocked")
    expect(result?.created_interface).toBeUndefined()
    expect(result && provedCompletedNativeImportIdentity(result)).toBeNull()
  })

  test("never treats contradictory post-dispatch blocked shapes as retryable", () => {
    const safeBlocked = {
      status: "blocked",
      stop: "writer_missing",
      external_ndms_writer_race_excluded: false,
      external_ndms_writer_race_accepted: true,
      system_configuration_save_performed: false,
      request_may_have_been_dispatched: false,
      wal_may_require_recovery: false,
      rollback_snapshot_may_be_retained: false,
      ownership_published: false,
    }

    for (const patch of [
      { stop: "none" },
      { external_ndms_writer_race_accepted: false },
      { request_may_have_been_dispatched: true },
      { rollback_snapshot_may_be_retained: true },
      { ownership_published: true },
      {
        created_interface: "Wireguard5",
        created_kernel_interface: "nwg5",
      },
      { forward_admission_state: "lease_busy" },
      { executor_stop: "transport_failed" },
    ]) {
      expect(
        parseNdmsNativeImportResult({ ...safeBlocked, ...patch })
      ).toBeNull()
    }
  })

  test("dirty WAL evidence locks even when an older status says blocked", () => {
    const dirtyWal = {
      status: "blocked",
      stop: "import_wal_not_clean",
      external_ndms_writer_race_excluded: false,
      external_ndms_writer_race_accepted: true,
      system_configuration_save_performed: false,
      request_may_have_been_dispatched: false,
      wal_may_require_recovery: false,
      rollback_snapshot_may_be_retained: false,
      ownership_published: false,
      delete_wal_readiness: "clean",
      import_wal_readiness: "unfinished",
    }
    const result = parseNdmsNativeImportResult(dirtyWal)

    expect(result).not.toBeNull()
    expect(result && ndmsNativeImportOutcome(result)).toBe("recovery_required")
    expect(
      parseNdmsNativeImportResult({
        ...dirtyWal,
        import_wal_readiness: "clean",
      })
    ).toBeNull()
    expect(
      parseNdmsNativeImportResult({
        ...dirtyWal,
        import_wal_readiness: undefined,
      })
    ).toBeNull()
  })

  test("does not copy unknown fields or unbounded diagnostic text into UI state", () => {
    expect(
      parseNdmsNativeImportResult({
        ...completed(),
        private_key: "must-not-render",
      })
    ).toBeNull()
    expect(
      parseNdmsNativeImportResult({
        ...completed(),
        executor_stop: "x".repeat(97),
      })
    ).toBeNull()
  })
})

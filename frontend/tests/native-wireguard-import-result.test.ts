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
  transaction_id: "0123456789abcdef0123456789abcdef",
  expected_interface: "Wireguard5",
  created_interface: "Wireguard5",
  created_kernel_interface: "nwg5",
  kind: "wireguard",
  delete_wal_readiness: "clean",
  import_wal_readiness: "clean",
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
      { created_interface: undefined },
      { created_kernel_interface: undefined },
      { created_kernel_interface: "nwg5/private" },
      { transaction_id: "not-a-transaction" },
      { kind: undefined },
      { delete_wal_readiness: "unfinished" },
      { import_wal_readiness: "unsafe" },
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
    })

    expect(result).not.toBeNull()
    expect(result && ndmsNativeImportOutcome(result)).toBe("recovery_required")
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
    ]) {
      expect(
        parseNdmsNativeImportResult({ ...safeBlocked, ...patch })
      ).toBeNull()
    }
  })

  test("dirty WAL evidence locks even when an older status says blocked", () => {
    const result = parseNdmsNativeImportResult({
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
    })

    expect(result).not.toBeNull()
    expect(result && ndmsNativeImportOutcome(result)).toBe("recovery_required")
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

import { afterEach, describe, expect, mock, test } from "bun:test"

import {
  NativeMutationTransportError,
  parseNdmsNativeDeleteResult,
  parseNdmsNativeImportRecoveryResult,
  parseNdmsNativeTombstoneForgetResult,
  postNdmsNativeDeleteOnce,
  postNdmsNativeImportRecoveryOnce,
  postNdmsNativeTombstoneForgetOnce,
} from "./native-mutation"
import { resetStepUpState } from "@/lib/step-up"

afterEach(() => resetStepUpState())

const terminalDelete = (interfaceName: string) => ({
  status: "save_acknowledged_unverified",
  stop: "none",
  external_writer_race_excluded: false,
  external_writer_race_accepted: true,
  global_save_scope_acknowledged: true,
  delete_perform_started: false,
  save_perform_started: false,
  request_may_have_been_dispatched: false,
  system_configuration_save_acknowledged: false,
  ownership_tombstone_durable: true,
  rollback_snapshot_retained: true,
  phase: "cleanup",
  interface_name: interfaceName,
  kind: "wireguard",
})

const noWorkImportRecovery = () => ({
  status: "no_work",
  stop: "none",
  ndms_import_request_dispatched: false,
  ndms_delete_dispatched: false,
  system_configuration_save_performed: false,
  external_ndms_writer_race_excluded: false,
  external_ndms_writer_race_accepted: false,
  delete_perform_started: false,
  request_may_have_been_dispatched: false,
  wal_may_require_recovery: false,
  ownership_published: false,
  rollback_snapshot_retired: false,
  wal_removed: false,
  delete_wal_readiness: "clean",
  import_wal_readiness: "clean",
})

const forgottenTombstone = (interfaceName = "Wireguard5") => ({
  status: "forgotten",
  stop: "none",
  interface_name: interfaceName,
  snapshot_state: "absent_durable",
  tombstone_state: "absent_durable",
  router_mutation_attempted: false,
  system_configuration_save_acknowledged: false,
  future_reappearance_is_foreign: true,
})

const tombstoneRevision = `ndms-native-owner-tombstone-v1-${"a".repeat(64)}`
const tombstoneForgetRequest = () => ({
  interface_name: "Wireguard5",
  expected_ownership_revision: tombstoneRevision,
  confirm_interface_name: "Wireguard5",
  rollback_discard_acknowledgement:
    "permanently_discard_rollback_data" as const,
  foreign_reappearance_acknowledgement:
    "accepted_reappearance_is_foreign" as const,
})

describe("native mutation identity boundaries", () => {
  test("accepts the exact managed Wireguard5..98 range", () => {
    expect(
      parseNdmsNativeDeleteResult(terminalDelete("Wireguard5"))
    ).not.toBeNull()
    expect(
      parseNdmsNativeDeleteResult(terminalDelete("Wireguard98"))
    ).not.toBeNull()
  })

  test("rejects adjacent Wireguard4 and Wireguard99 identities", () => {
    expect(parseNdmsNativeDeleteResult(terminalDelete("Wireguard4"))).toBeNull()
    expect(
      parseNdmsNativeDeleteResult(terminalDelete("Wireguard99"))
    ).toBeNull()
  })

  test("rejects a forged terminal transport failure", () => {
    expect(
      parseNdmsNativeDeleteResult({
        ...terminalDelete("Wireguard5"),
        transport_outcome: "transport_failed",
      })
    ).toBeNull()
  })

  test("checks request targets before any fetch", async () => {
    const fetchImpl = mock(() =>
      Promise.resolve(Response.json(terminalDelete("Wireguard5")))
    )
    const revision = `ndms-native-owner-v3-${"a".repeat(64)}`

    await expect(
      postNdmsNativeDeleteOnce(
        {
          interface_name: "Wireguard4",
          expected_ownership_revision: revision,
          confirm_label: "Wireguard4",
        },
        fetchImpl
      )
    ).rejects.toMatchObject({ code: "rejected" })
    expect(fetchImpl).toHaveBeenCalledTimes(0)
  })

  test("keeps a mismatched typed delete result outcome-unknown", async () => {
    const fetchImpl = mock(() =>
      Promise.resolve(Response.json(terminalDelete("Wireguard6")))
    )
    const revision = `ndms-native-owner-v3-${"a".repeat(64)}`

    await expect(
      postNdmsNativeDeleteOnce(
        {
          interface_name: "Wireguard5",
          expected_ownership_revision: revision,
          confirm_label: "Wireguard5",
        },
        fetchImpl
      )
    ).rejects.toMatchObject({ code: "outcome_unknown" })
    expect(fetchImpl).toHaveBeenCalledTimes(1)
  })
})

describe("native mutation response trust", () => {
  test("accepts only a coherent bodyless no-work result", () => {
    expect(
      parseNdmsNativeImportRecoveryResult(noWorkImportRecovery())
    ).not.toBeNull()
    expect(
      parseNdmsNativeImportRecoveryResult({
        ...noWorkImportRecovery(),
        transaction_id: "a".repeat(32),
      })
    ).toBeNull()
  })

  test("treats 500 and 503 as outcome-unknown", async () => {
    for (const status of [500, 503]) {
      const fetchImpl = mock(() =>
        Promise.resolve(new Response("", { status }))
      )
      await expect(postNdmsNativeImportRecoveryOnce(fetchImpl)).rejects.toEqual(
        new NativeMutationTransportError("outcome_unknown")
      )
    }
  })

  test("treats a malformed 200 as outcome-unknown", async () => {
    const fetchImpl = mock(() =>
      Promise.resolve(
        Response.json({ ...noWorkImportRecovery(), wal_removed: true })
      )
    )
    await expect(
      postNdmsNativeImportRecoveryOnce(fetchImpl)
    ).rejects.toMatchObject({ code: "outcome_unknown" })
  })

  test("accepts stable cleanup, consent, ambiguity and pre-guard truth", () => {
    const record = {
      ...noWorkImportRecovery(),
      status: "recovery_required",
      wal_may_require_recovery: true,
      delete_wal_readiness: "clean",
      import_wal_readiness: "unfinished",
      expected_interface: "Wireguard5",
      kind: "wireguard",
      phase: "response_recorded",
      recovery_action: "rollback_delete_exact_owned",
    } as const
    const consent = {
      ...record,
      stop: "external_writer_race_not_accepted",
    } as const
    expect(parseNdmsNativeImportRecoveryResult(consent)).not.toBeNull()

    const ambiguity = {
      ...record,
      stop: "delete_transport_ambiguous",
      phase: "delete_may_be_inflight",
      external_ndms_writer_race_accepted: true,
      delete_perform_started: true,
      request_may_have_been_dispatched: true,
      ndms_delete_dispatched: true,
      recovery_admission_state: "admitted",
      recovery_dispatch_state: "step_failed",
      recovery_failed_step: "delete_exact_owned_target",
      delete_transport_outcome: "transport_failed",
    } as const
    expect(parseNdmsNativeImportRecoveryResult(ambiguity)).not.toBeNull()

    const beforeGuard = {
      ...ambiguity,
      stop: "delete_guard_rejected",
      delete_perform_started: false,
      request_may_have_been_dispatched: false,
      ndms_delete_dispatched: false,
    } as const
    expect(parseNdmsNativeImportRecoveryResult(beforeGuard)).not.toBeNull()

    const stableCleanup = {
      ...record,
      status: "completed",
      stop: "none",
      phase: "target_verified",
      recovery_action: "complete_rollback",
      recovery_admission_state: "admitted",
      recovery_dispatch_state: "completed",
      wal_may_require_recovery: false,
      rollback_snapshot_retired: true,
      wal_removed: true,
    } as const
    expect(parseNdmsNativeImportRecoveryResult(stableCleanup)).not.toBeNull()
  })

  test("requires the retained trace after a destructive delete prefix", () => {
    const postDeleteFailure = {
      ...noWorkImportRecovery(),
      status: "recovery_required",
      stop: "absence_wal_publish_failed",
      external_ndms_writer_race_accepted: true,
      delete_perform_started: true,
      request_may_have_been_dispatched: true,
      ndms_delete_dispatched: true,
      wal_may_require_recovery: true,
      expected_interface: "Wireguard5",
      kind: "wireguard",
      phase: "delete_may_be_inflight",
      delete_wal_readiness: "clean",
      import_wal_readiness: "unfinished",
      recovery_action: "rollback_delete_exact_owned",
      recovery_admission_state: "admitted",
      recovery_dispatch_state: "step_failed",
      recovery_failed_step: "advance_wal_absence_verified",
      delete_transport_outcome: "http_status_not_200",
    } as const
    expect(
      parseNdmsNativeImportRecoveryResult(postDeleteFailure)
    ).not.toBeNull()
    expect(
      parseNdmsNativeImportRecoveryResult({
        ...postDeleteFailure,
        delete_perform_started: false,
        request_may_have_been_dispatched: false,
        ndms_delete_dispatched: false,
        delete_transport_outcome: undefined,
      })
    ).toBeNull()
  })

  test("keeps exact pre-core 4xx distinguishable from ambiguity", async () => {
    const fetchImpl = mock(() =>
      Promise.resolve(new Response("", { status: 428 }))
    )
    await expect(
      postNdmsNativeImportRecoveryOnce(fetchImpl)
    ).rejects.toMatchObject({ code: "rejected" })
  })

  test("propagates a network failure for the caller to latch unknown", async () => {
    const fetchImpl = mock(() => Promise.reject(new TypeError("offline")))
    await expect(
      postNdmsNativeImportRecoveryOnce(fetchImpl)
    ).rejects.toBeInstanceOf(TypeError)
  })

  test("sends fresh owner acceptance only for the explicit invocation", async () => {
    const fetchImpl = mock((_input: RequestInfo | URL, init?: RequestInit) => {
      const headers = new Headers(init?.headers)
      expect(
        headers.get("X-Keen-Pbr-External-Ndms-Writer-Race-Acceptance")
      ).toBe("owner-accepted")
      return Promise.resolve(
        Response.json({
          ...noWorkImportRecovery(),
          external_ndms_writer_race_accepted: true,
        })
      )
    })

    await expect(
      postNdmsNativeImportRecoveryOnce(true, fetchImpl)
    ).resolves.toMatchObject({
      status: "no_work",
      external_ndms_writer_race_accepted: true,
    })
    expect(fetchImpl).toHaveBeenCalledTimes(1)
  })

  test("binds the response acceptance trace to this exact request", async () => {
    const acceptedResponse = mock(() =>
      Promise.resolve(
        Response.json({
          ...noWorkImportRecovery(),
          external_ndms_writer_race_accepted: true,
        })
      )
    )
    await expect(
      postNdmsNativeImportRecoveryOnce(false, acceptedResponse)
    ).rejects.toMatchObject({ code: "outcome_unknown" })

    const absentResponse = mock(() =>
      Promise.resolve(Response.json(noWorkImportRecovery()))
    )
    await expect(
      postNdmsNativeImportRecoveryOnce(true, absentResponse)
    ).rejects.toMatchObject({ code: "outcome_unknown" })
  })
})

describe("native tombstone forget transport", () => {
  test("accepts only truthful terminal and partial artifact states", () => {
    expect(
      parseNdmsNativeTombstoneForgetResult(forgottenTombstone())
    ).not.toBeNull()
    expect(
      parseNdmsNativeTombstoneForgetResult({
        ...forgottenTombstone(),
        status: "blocked",
        stop: "ownership_changed",
        snapshot_state: "unknown",
        tombstone_state: "unknown",
        future_reappearance_is_foreign: false,
      })
    ).not.toBeNull()
    expect(
      parseNdmsNativeTombstoneForgetResult({
        ...forgottenTombstone(),
        status: "blocked",
        stop: "snapshot_retirement_failed",
        snapshot_state: "retained",
        tombstone_state: "retained",
        future_reappearance_is_foreign: false,
      })
    ).not.toBeNull()
    expect(
      parseNdmsNativeTombstoneForgetResult({
        ...forgottenTombstone(),
        status: "recovery_required",
        stop: "tombstone_retirement_failed",
        tombstone_state: "retained",
        future_reappearance_is_foreign: false,
      })
    ).not.toBeNull()
    expect(
      parseNdmsNativeTombstoneForgetResult({
        ...forgottenTombstone(),
        status: "recovery_required",
        stop: "snapshot_retirement_failed",
        snapshot_state: "retained",
        tombstone_state: "retained",
        future_reappearance_is_foreign: false,
      })
    ).not.toBeNull()

    for (const forged of [
      { ...forgottenTombstone(), router_mutation_attempted: true },
      { ...forgottenTombstone(), snapshot_state: "retained" },
      { ...forgottenTombstone(), transaction_id: "private" },
      {
        ...forgottenTombstone(),
        status: "blocked",
        stop: "snapshot_retirement_failed",
        snapshot_state: "unknown",
        tombstone_state: "unknown",
        future_reappearance_is_foreign: false,
      },
      {
        ...forgottenTombstone(),
        status: "blocked",
        stop: "tombstone_retirement_failed",
        snapshot_state: "unknown",
        tombstone_state: "unknown",
        future_reappearance_is_foreign: false,
      },
      {
        ...forgottenTombstone(),
        status: "recovery_required",
        stop: "ownership_absent",
        tombstone_state: "retained",
        future_reappearance_is_foreign: false,
      },
    ]) {
      expect(parseNdmsNativeTombstoneForgetResult(forged)).toBeNull()
    }
  })

  test("rejects a non-exact request before fetch", async () => {
    const fetchImpl = mock(() =>
      Promise.resolve(Response.json(forgottenTombstone()))
    )
    await expect(
      postNdmsNativeTombstoneForgetOnce(
        {
          ...tombstoneForgetRequest(),
          confirm_interface_name: "Wireguard6",
        },
        fetchImpl
      )
    ).rejects.toMatchObject({ code: "rejected" })
    expect(fetchImpl).toHaveBeenCalledTimes(0)
  })

  test("posts exact JSON once without mutation headers", async () => {
    const fetchImpl = mock((input: RequestInfo | URL, init?: RequestInit) => {
      expect(input).toBe(
        "/api/system/ndms/interfaces/retained-deletions/forget"
      )
      expect(init?.method).toBe("POST")
      expect(init?.cache).toBe("no-store")
      expect(init?.redirect).toBe("error")
      const headers = new Headers(init?.headers)
      expect(headers.get("Content-Type")).toBe("application/json")
      expect(
        headers.get("X-Keen-Pbr-External-Ndms-Writer-Race-Acceptance")
      ).toBeNull()
      expect(JSON.parse(String(init?.body))).toEqual(tombstoneForgetRequest())
      return Promise.resolve(Response.json(forgottenTombstone()))
    })

    await expect(
      postNdmsNativeTombstoneForgetOnce(tombstoneForgetRequest(), fetchImpl)
    ).resolves.toMatchObject({ status: "forgotten" })
    expect(fetchImpl).toHaveBeenCalledTimes(1)
  })

  test("does not trust a response for another retained deletion", async () => {
    const fetchImpl = mock(() =>
      Promise.resolve(Response.json(forgottenTombstone("Wireguard6")))
    )
    await expect(
      postNdmsNativeTombstoneForgetOnce(tombstoneForgetRequest(), fetchImpl)
    ).rejects.toMatchObject({ code: "outcome_unknown" })
    expect(fetchImpl).toHaveBeenCalledTimes(1)
  })
})

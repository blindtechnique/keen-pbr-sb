import { afterEach, describe, expect, mock, test } from "bun:test"

import {
  NativeMutationTransportError,
  parseNdmsNativeDeleteResult,
  parseNdmsNativeImportRecoveryResult,
  postNdmsNativeDeleteOnce,
  postNdmsNativeImportRecoveryOnce,
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
  wal_may_require_recovery: false,
  ownership_published: false,
  wal_removed: false,
  delete_wal_readiness: "clean",
  import_wal_readiness: "clean",
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
})

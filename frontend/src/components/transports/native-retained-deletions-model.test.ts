import { describe, expect, test } from "bun:test"

import {
  NdmsNativeRetainedDeletionBlocker,
  NdmsNativeRetainedDeletionDeferredCheck,
} from "@/api/generated/model"
import {
  NDMS_NATIVE_TOMBSTONE_FORGET_ARTIFACT_STATES,
  NDMS_NATIVE_TOMBSTONE_FORGET_STATUSES,
  NDMS_NATIVE_TOMBSTONE_FORGET_STOPS,
  type NdmsNativeTombstoneForgetResult,
} from "@/api/native-mutation"
import { enTranslation } from "@/i18n/en"
import { ruTranslation } from "@/i18n/ru"

import {
  retainedDeletionBlockerKey,
  retainedDeletionDeferredCheckKey,
  tombstoneForgetArtifactStateKey,
  tombstoneForgetDisposition,
  tombstoneForgetOutcomeKey,
  tombstoneForgetStopKey,
} from "./native-retained-deletions-model"

function lookup(tree: unknown, key: string): unknown {
  return key
    .split(".")
    .reduce<unknown>(
      (node, segment) =>
        node && typeof node === "object"
          ? (node as Record<string, unknown>)[segment]
          : undefined,
      tree
    )
}

function bothLocales(key: string) {
  expect(lookup(enTranslation, key), key).toBeTypeOf("string")
  expect(lookup(ruTranslation, key), key).toBeTypeOf("string")
}

const result = (
  status: NdmsNativeTombstoneForgetResult["status"],
  stop: NdmsNativeTombstoneForgetResult["stop"]
): NdmsNativeTombstoneForgetResult => ({
  status,
  stop,
  interface_name: "Wireguard5",
  snapshot_state: status === "forgotten" ? "absent_durable" : "unknown",
  tombstone_state: status === "forgotten" ? "absent_durable" : "unknown",
  router_mutation_attempted: false,
  system_configuration_save_acknowledged: false,
  future_reappearance_is_foreign: status === "forgotten",
})

describe("retained native deletion model", () => {
  test("keeps partial forget recovery in its own journal family", () => {
    expect(
      tombstoneForgetDisposition(
        result("recovery_required", "snapshot_retirement_failed")
      )
    ).toEqual({ state: "recovery", recovery: "forget" })
    expect(tombstoneForgetDisposition(result("forgotten", "none"))).toEqual({
      state: "clear",
    })
    expect(
      tombstoneForgetDisposition(result("blocked", "ownership_changed"))
    ).toEqual({ state: "clear" })
  })

  test("redirects only exact cross-WAL stops without retrying a request", () => {
    expect(
      tombstoneForgetDisposition(
        result("blocked", "import_wal_not_authoritatively_clean")
      )
    ).toEqual({ state: "redirect_recovery", recovery: "import" })
    expect(
      tombstoneForgetDisposition(
        result("recovery_required", "delete_wal_unfinished")
      )
    ).toEqual({ state: "redirect_recovery", recovery: "delete" })
    expect(
      tombstoneForgetDisposition(result("blocked", "delete_wal_unsafe"))
    ).toEqual({ state: "redirect_recovery", recovery: "delete" })
  })

  test("names every public blocker, deferred check, stop and outcome", () => {
    for (const blocker of Object.values(NdmsNativeRetainedDeletionBlocker)) {
      bothLocales(retainedDeletionBlockerKey(blocker))
    }
    for (const check of Object.values(
      NdmsNativeRetainedDeletionDeferredCheck
    )) {
      bothLocales(retainedDeletionDeferredCheckKey(check))
    }
    for (const stop of NDMS_NATIVE_TOMBSTONE_FORGET_STOPS) {
      bothLocales(tombstoneForgetStopKey(stop))
    }
    for (const state of NDMS_NATIVE_TOMBSTONE_FORGET_ARTIFACT_STATES) {
      bothLocales(tombstoneForgetArtifactStateKey(state))
    }
    for (const status of NDMS_NATIVE_TOMBSTONE_FORGET_STATUSES) {
      bothLocales(tombstoneForgetOutcomeKey(result(status, "none")))
    }
    for (const key of [
      "transports.nativeMutation.forget.title",
      "transports.nativeMutation.forget.description",
      "transports.nativeMutation.forget.dialogTitle",
      "transports.nativeMutation.forget.rollbackAcknowledgement",
      "transports.nativeMutation.forget.foreignAcknowledgement",
      "transports.nativeMutation.forget.recoveryTitle",
      "transports.nativeMutation.forget.recoveryDescription",
    ]) {
      bothLocales(key)
    }
  })
})

import { expect, test } from "bun:test"

import {
  nativeWireGuardImportIntakeIsLocked,
  nativeWireGuardImportOperationSurvivesContextChange,
} from "@/lib/native-wireguard-import-operation"

test("in-flight and ambiguous native imports cannot be reset by new intake", () => {
  for (const status of [
    "preflighting",
    "sending",
    "unknown",
    "recovery-locked",
  ] as const) {
    expect(nativeWireGuardImportIntakeIsLocked({ status })).toBe(true)
  }
  expect(
    nativeWireGuardImportIntakeIsLocked({
      status: "result",
      outcome: "recovery_required",
    })
  ).toBe(true)
  expect(nativeWireGuardImportIntakeIsLocked({ status: "idle" })).toBe(false)
})

test("late context updaters preserve every in-flight and terminal result", () => {
  for (const operation of [
    { status: "preflighting" },
    { status: "sending" },
    { status: "result", outcome: "blocked" },
    { status: "result", outcome: "recovery_required" },
    { status: "result", outcome: "completed" },
  ] as const) {
    expect(nativeWireGuardImportOperationSurvivesContextChange(operation)).toBe(
      true
    )
  }
  expect(
    nativeWireGuardImportOperationSurvivesContextChange({ status: "idle" })
  ).toBe(false)
})

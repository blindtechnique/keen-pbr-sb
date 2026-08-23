import { expect, test } from "bun:test"

import {
  nativeWireGuardImportIntakeIsLocked,
  nativeWireGuardImportOperationSurvivesContextChange,
  nativeWireGuardImportShouldContinueInBackground,
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

test("accepted ambiguous imports leave the form and finish in background", () => {
  for (const operation of [
    { status: "unknown" },
    { status: "recovery-locked" },
    { status: "result", outcome: "recovery_required" },
  ] as const) {
    expect(nativeWireGuardImportShouldContinueInBackground(operation)).toBe(
      true
    )
  }

  for (const operation of [
    { status: "preflight-error" },
    { status: "not-imported" },
    { status: "selection-expired" },
    { status: "result", outcome: "blocked" },
    { status: "result", outcome: "completed" },
  ] as const) {
    expect(nativeWireGuardImportShouldContinueInBackground(operation)).toBe(
      false
    )
  }
})

test("background handoff paints progress and bypasses the discard-draft close", async () => {
  const formSource = await Bun.file(
    new URL(
      "../src/components/transports/transport-config-dialog.tsx",
      import.meta.url
    )
  ).text()
  const pageSource = await Bun.file(
    new URL("../src/components/shared/upsert-page.tsx", import.meta.url)
  ).text()
  const contextSource = await Bun.file(
    new URL("../src/components/shared/upsert-page-context.ts", import.meta.url)
  ).text()

  expect(
    formSource.match(/onImportHandedOff={finishHandedOffNativeImport}/g)
  ).toHaveLength(2)
  expect(formSource).not.toContain("onImportHandedOff={close}")
  expect(formSource).toContain("}, 900)")
  expect(pageSource).toContain(
    "const complete = useCallback(() => onClose?.(), [onClose])"
  )
  expect(pageSource).toContain("() => ({ close, complete })")
  expect(contextSource).toContain("useContext(UpsertCloseContext).complete")
})

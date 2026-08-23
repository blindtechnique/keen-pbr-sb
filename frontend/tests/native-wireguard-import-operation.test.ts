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
  const transportUpsertSource = await Bun.file(
    new URL("../src/pages/transport-upsert-page.tsx", import.meta.url)
  ).text()
  const transportsSource = await Bun.file(
    new URL("../src/pages/transports-page.tsx", import.meta.url)
  ).text()

  expect(
    formSource.match(/onImportHandedOff={finishHandedOffNativeImport}/g)
  ).toHaveLength(2)
  expect(formSource).not.toContain("onImportHandedOff={close}")
  expect(formSource).toContain("}, 900)")
  expect(formSource).toContain(
    'toast.loading(t("transports.nativeImport.importingToast")'
  )
  expect(formSource).toContain("id: NATIVE_WIREGUARD_IMPORT_PROGRESS_TOAST_ID")
  expect(transportUpsertSource).toContain(
    '"transports.nativeImport.importedToast"'
  )
  expect(transportUpsertSource).toContain(
    "id: NATIVE_WIREGUARD_IMPORT_PROGRESS_TOAST_ID"
  )
  expect(transportsSource).toContain(
    'toast.success(t("transports.nativeImport.importedToast"), {'
  )
  expect(transportsSource).toContain(
    "id: NATIVE_WIREGUARD_IMPORT_PROGRESS_TOAST_ID"
  )
  expect(pageSource).toContain(
    "const complete = useCallback(() => onClose?.(), [onClose])"
  )
  expect(pageSource).toContain("() => ({ close, complete })")
  expect(contextSource).toContain("useContext(UpsertCloseContext).complete")
})

test("native import owns focus and blocks competing create UI until completion", async () => {
  const cardSource = await Bun.file(
    new URL(
      "../src/components/transports/native-wireguard-import-card.tsx",
      import.meta.url
    )
  ).text()
  const formSource = await Bun.file(
    new URL(
      "../src/components/transports/transport-config-dialog.tsx",
      import.meta.url
    )
  ).text()
  const pageSource = await Bun.file(
    new URL("../src/pages/transports-page.tsx", import.meta.url)
  ).text()

  expect(cardSource).toContain("disabled={uriIntakeLocked}")
  expect(cardSource).toContain("previewRef.current?.focus()")
  expect(cardSource).toContain("onDisplayNameRequired?.()")
  expect(formSource).toContain("displayNameInputRef.current?.focus()")
  expect(
    formSource.match(/onDisplayNameRequired={focusRequiredDisplayName}/g)
  ).toHaveLength(2)
  expect(formSource).toContain(
    '"border-primary bg-primary/10 shadow-sm ring-2 ring-primary/20"'
  )
  expect(pageSource).toContain("disabled={nativeImportInProgress}")
  expect(pageSource).toContain(
    "candidates={nativeImportInProgress ? [] : routeOfferCandidates}"
  )
})

import { expect, test } from "bun:test"

test("native recovery timers use current callbacks without polling resetting their deadline", async () => {
  const source = await Bun.file(
    new URL(
      "../src/components/transports/native-mutation-recovery.tsx",
      import.meta.url
    )
  ).text()
  for (const kind of ["Import", "Delete"]) {
    const lower = kind.toLowerCase()
    expect(source).toContain(
      `const on${kind}RecoveryTimer = useEffectEvent(() => void recover${kind}())`
    )
    expect(source).toContain(`on${kind}RecoveryTimer()`)
    expect(source).toContain(`}, [busy, ${lower}NeedsRecovery, finishedPass])`)
    expect(source).not.toContain(
      `}, [busy, ${lower}NeedsRecovery, finishedPass, recover${kind}])`
    )
  }
})

test("a clean native WAL cannot erase the unfinished panel completion plan", async () => {
  const source = await Bun.file(
    new URL(
      "../src/components/transports/native-mutation-recovery.tsx",
      import.meta.url
    )
  ).text()
  expect(source).not.toContain("clearStagedNativeWireGuardImportCompletion")
  expect(source).toContain("readBackgroundNativeWireGuardImportCompletionTag")
  expect(source).toContain("const onImportCompletionTimer = useEffectEvent")
  const completionWorker = source.slice(
    source.indexOf("const onImportCompletionTimer"),
    source.indexOf("const recoverDelete")
  )
  expect(completionWorker).not.toContain("postNdmsNativeImportRecoveryOnce")
  expect(completionWorker).toContain("onImportNoWork?.()")
})

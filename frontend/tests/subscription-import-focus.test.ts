import { expect, test } from "bun:test"

import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"

test("subscription import owns focus and cannot fall through to a second save", async () => {
  const formSource = await Bun.file(
    new URL(
      "../src/components/transports/transport-config-dialog.tsx",
      import.meta.url
    )
  ).text()
  const dialogSource = await Bun.file(
    new URL(
      "../src/components/transports/subscription-import-dialog.tsx",
      import.meta.url
    )
  ).text()

  expect(formSource).toContain(
    "nativeImportPreviewOnly || subscriptionLinkActive"
  )
  expect(formSource).toContain(
    "subscriptionOfferButtonRef.current?.scrollIntoView"
  )
  expect(formSource).toContain("subscriptionOfferButtonRef.current?.focus()")
  expect(formSource).toContain("ref={subscriptionOfferButtonRef}")
  expect(formSource).toContain("onDirtyChange(false)")
  expect(formSource).toContain("complete()")
  expect(formSource).toContain('t("transports.subscriptionImport.completed"')
  expect(formSource).toContain("onResultsDismiss={() => {")

  expect(dialogSource).toContain("`subscription-tag-${firstProblem.line}`")
  expect(dialogSource).toContain(
    '"border-destructive bg-destructive/5 ring-1 ring-destructive/20"'
  )
  expect(dialogSource).toContain("response.data.results.every(")
  expect(dialogSource).toContain('result.outcome !== "failed"')
  expect(dialogSource).toContain('t("transports.subscriptionImport.applying")')
  expect(dialogSource).toContain("if (results) {")
  expect(dialogSource).toContain("onResultsDismiss()")
})

test("partial results describe the linked running connections", () => {
  expect(ruTranslation.transports.subscriptionImport.nextSteps).toContain(
    "уже запущены"
  )
  expect(enTranslation.transports.subscriptionImport.nextSteps).toContain(
    "already running"
  )
})

test("recovery attempt counters stay in backend data but not in the UI", async () => {
  const pageSource = await Bun.file(
    new URL("../src/pages/transports-page.tsx", import.meta.url)
  ).text()

  expect(pageSource).not.toContain("item.retry_count")
  expect(pageSource).not.toContain('t("transports.retryCount")')
})

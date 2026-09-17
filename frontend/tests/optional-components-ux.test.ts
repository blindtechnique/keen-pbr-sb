import { describe, expect, test } from "bun:test"
import { readFileSync } from "node:fs"

const source = (path: string) =>
  readFileSync(new URL(`../src/${path}`, import.meta.url), "utf8")

describe("optional component and native import UX", () => {
  test("an absent sing-box is a warning with the existing in-panel installer", () => {
    const page = source("pages/transports-page.tsx")
    expect(page).toMatch(
      /sing_box_installed === false[\s\S]*?<Alert variant="warning">/
    )
    expect(page).toContain("<SingBoxInstallButton")
    expect(page).not.toContain("raw.githubusercontent.com/blindtechnique")
  })

  test("creating a native tunnel explains the router change without a consent checkbox", () => {
    const card = source(
      "components/transports/native-wireguard-import-card.tsx"
    )
    expect(card).toContain('t("transports.nativeImport.routerCreationNotice")')
    expect(card).not.toContain("ownerRiskAccepted")
    expect(card).not.toContain('type="checkbox"')
    // Explicit creation still enters the normal single-request import path.
    expect(card).toContain("onClick={() => void submitImport()}")
    expect(card).toContain("postNdmsNativeImportSecretOnce")
  })
})

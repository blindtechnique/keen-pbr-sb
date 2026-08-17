import { describe, expect, test } from "bun:test"

const pagePath = new URL("../src/pages/nfqws-page.tsx", import.meta.url)

describe("nfqws operation rollback isolation", () => {
  test("never offers the mutable global rollback snapshot from an operation result", async () => {
    const source = await Bun.file(pagePath).text()

    // A step-up denial, busy lease or preflight refusal may happen before this
    // request creates a snapshot. Even after success another administrator can
    // replace the shared snapshot before the click. Until the API has an
    // expected-revision CAS, the nfqws result dialog must expose no rollback.
    expect(source).not.toContain("rollbackBackup")
    expect(source).not.toContain("rollbackAvailable")
    expect(source).not.toContain("onRollback")
  })
})

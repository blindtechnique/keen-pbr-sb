import { describe, expect, test } from "bun:test"

import { nfqwsUpgradeAllowed } from "./nfqws-upgrade-capability"

describe("nfqws upgrade capability", () => {
  test("an explicit backend refusal wins over update availability", () => {
    expect(
      nfqwsUpgradeAllowed({
        available: false,
        mode: "blocked_fail_closed",
        exact_previous_ipk: false,
        verified_target_ipk: false,
        exact_opkg_metadata_rollback: false,
        boot_recovery: false,
        reason: "not transactionally recoverable",
      })
    ).toBe(false)
  })

  test("an older backend without a safety capability is fail-closed", () => {
    expect(nfqwsUpgradeAllowed(undefined)).toBe(false)
  })
})

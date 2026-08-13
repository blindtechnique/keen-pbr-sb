import { describe, expect, test } from "bun:test"

import {
  nfqwsUpgradeAllowed,
  nfqwsUpgradeBlockKind,
} from "./nfqws-upgrade-capability"

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

  test("an explicit guarded opkg capability remains available with honest limits", () => {
    expect(
      nfqwsUpgradeAllowed({
        available: true,
        mode: "guarded_opkg",
        exact_previous_ipk: false,
        verified_target_ipk: false,
        exact_opkg_metadata_rollback: false,
        boot_recovery: false,
        limitation: "file restore is not an exact package rollback",
      })
    ).toBe(true)
  })

  test("an unknown advertised mode stays fail-closed", () => {
    expect(
      nfqwsUpgradeAllowed({
        available: true,
        mode: "future_unreviewed_mode",
        exact_previous_ipk: true,
        verified_target_ipk: true,
        exact_opkg_metadata_rollback: true,
        boot_recovery: true,
      })
    ).toBe(false)
  })

  test("maps only the declared metadata block to its precise local explanation", () => {
    expect(
      nfqwsUpgradeBlockKind({
        available: false,
        mode: "guarded_opkg",
        exact_previous_ipk: false,
        verified_target_ipk: false,
        exact_opkg_metadata_rollback: false,
        boot_recovery: false,
        blocked_reason: "nfqws_package_metadata_unverified",
      })
    ).toBe("metadata_unverified")
    expect(nfqwsUpgradeBlockKind(undefined)).toBe("unavailable")
  })
})

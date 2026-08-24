import { describe, expect, test } from "bun:test"

import {
  nfqwsUpgradeMissingGuarantees,
  type NfqwsUpgradeCapability,
} from "../src/lib/nfqws-upgrade-capability"

const complete: NfqwsUpgradeCapability = {
  available: true,
  mode: "guarded_opkg",
  exact_previous_ipk: true,
  verified_target_ipk: true,
  exact_opkg_metadata_rollback: true,
  boot_recovery: true,
}

describe("nfqws upgrade guarantees", () => {
  // The limitation alert used to be keyed on the mode string alone, which
  // outlived the guarantees it warned about: the build that pins and
  // verifies the target IPK, keeps the exact previous one and repairs an
  // interrupted attempt still told the operator none of that happens.
  test("a router with every guarantee has nothing to warn about", () => {
    expect(nfqwsUpgradeMissingGuarantees(complete)).toEqual([])
  })

  test("each absent guarantee is named on its own", () => {
    expect(
      nfqwsUpgradeMissingGuarantees({ ...complete, exact_previous_ipk: false })
    ).toEqual(["exactPrevious"])
    expect(
      nfqwsUpgradeMissingGuarantees({ ...complete, verified_target_ipk: false })
    ).toEqual(["verifiedTarget"])
    expect(
      nfqwsUpgradeMissingGuarantees({
        ...complete,
        exact_opkg_metadata_rollback: false,
      })
    ).toEqual(["metadataRollback"])
    expect(
      nfqwsUpgradeMissingGuarantees({ ...complete, boot_recovery: false })
    ).toEqual(["bootRecovery"])
  })

  // An older backend publishes no capability at all. Unknown is not a
  // promise, so the operator is told every guarantee is missing rather than
  // shown a reassuring blank.
  test("no capability promises nothing", () => {
    expect(nfqwsUpgradeMissingGuarantees(undefined)).toEqual([
      "exactPrevious",
      "verifiedTarget",
      "metadataRollback",
      "bootRecovery",
    ])
  })
})

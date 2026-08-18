import { describe, expect, test } from "bun:test"

import type { NfqwsUpdateStatus } from "@/api/nfqws"

import {
  nfqwsUpgradeAllowed,
  nfqwsUpgradeBlockKind,
  nfqwsUpgradeButton,
  type NfqwsUpgradeCapability,
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

const guarded: NfqwsUpgradeCapability = {
  available: true,
  mode: "guarded_opkg",
  exact_previous_ipk: false,
  verified_target_ipk: false,
  exact_opkg_metadata_rollback: false,
  boot_recovery: false,
}

const updateOffered: NfqwsUpdateStatus = {
  ok: true,
  installed: true,
  current: "70.4",
  latest: "70.5",
  available: true,
}

describe("nfqws upgrade button", () => {
  test("an update the router can install enables the button", () => {
    const state = nfqwsUpgradeButton(updateOffered, guarded, false, false)
    expect(state.enabled).toBe(true)
    expect(state.tooltipKey).toBe("nfqws.upgradeTip.available")
  })

  test("no newer version disables the button and says so", () => {
    const state = nfqwsUpgradeButton(
      { ...updateOffered, latest: "70.4", available: false },
      guarded,
      false,
      false
    )
    expect(state.enabled).toBe(false)
    expect(state.tooltipKey).toBe("nfqws.upgradeTip.upToDate")
  })

  test("an unfinished check never claims the install is up to date", () => {
    expect(nfqwsUpgradeButton(undefined, guarded, false, true)).toEqual({
      enabled: false,
      tooltipKey: "nfqws.upgradeTip.checking",
    })
    expect(nfqwsUpgradeButton(undefined, guarded, false, false)).toEqual({
      enabled: false,
      tooltipKey: "nfqws.upgradeTip.checking",
    })
  })

  test("any operation in flight outranks the version verdict", () => {
    const state = nfqwsUpgradeButton(updateOffered, guarded, true, false)
    expect(state.enabled).toBe(false)
    expect(state.tooltipKey).toBe("nfqws.upgradeTip.busy")
  })

  test("unverified package metadata outranks an optimistic available flag", () => {
    const state = nfqwsUpgradeButton(
      { ...updateOffered, package_metadata_verified: false },
      { ...guarded, available: false, blocked_reason: "nfqws_package_metadata_unverified" },
      false,
      false
    )
    expect(state.enabled).toBe(false)
    expect(state.tooltipKey).toBe("nfqws.upgradeTip.metadataUnverified")
  })

  test("an offered update the backend will not perform stays disabled", () => {
    const state = nfqwsUpgradeButton(updateOffered, undefined, false, false)
    expect(state.enabled).toBe(false)
    expect(state.tooltipKey).toBe("nfqws.upgradeTip.blocked")
  })
})

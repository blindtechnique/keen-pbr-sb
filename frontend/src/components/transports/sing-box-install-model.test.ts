import { describe, expect, it } from "bun:test"

import { enTranslation } from "@/i18n/en"
import { ruTranslation } from "@/i18n/ru"
import {
  SingBoxInstallCapabilityBlockersItem,
  SingBoxInstallCapabilityOperation,
  SingBoxInstallResultInstallOutcome,
  SingBoxInstallResultReleaseVerdict,
  type SingBoxInstallCapability,
} from "@/api/generated/model"
import {
  singBoxInstallBlockerKey,
  singBoxInstallButton,
  singBoxInstallDisplayableBlockers,
  singBoxInstallFailureTitleKey,
  singBoxInstallLeftDown,
  singBoxInstallMayHaveApplied,
  singBoxInstallNeedsTransportConsent,
  singBoxInstallOutcomeKey,
  singBoxInstallPhaseKey,
  singBoxInstallRefusedBlockers,
  singBoxInstallResultTone,
  singBoxInstallStagedVersion,
  singBoxInstallVerdictKey,
} from "@/components/transports/sing-box-install-model"

function lookup(tree: unknown, key: string): unknown {
  return key
    .split(".")
    .reduce<unknown>(
      (node, segment) =>
        node && typeof node === "object"
          ? (node as Record<string, unknown>)[segment]
          : undefined,
      tree
    )
}

function bothLocales(key: string) {
  expect(lookup(enTranslation, key), key).toBeTypeOf("string")
  expect(lookup(ruTranslation, key), key).toBeTypeOf("string")
}

const capability = (
  overrides: Partial<SingBoxInstallCapability> = {}
): SingBoxInstallCapability => ({
  available: true,
  operation: SingBoxInstallCapabilityOperation.install,
  pinned_version: "1.13.14",
  blockers: [],
  verified_archive_checksum: true,
  signed_release: false,
  exact_rollback: false,
  ...overrides,
})

describe("the sing-box button", () => {
  it("offers an install when sing-box is absent", () => {
    const state = singBoxInstallButton(capability(), false, false)
    expect(state.action).toBe("install")
    expect(state.enabled).toBe(true)
    expect(state.labelKey).toBe("transports.singBoxInstall.actionInstall")
    expect(state.needsConsent).toBe(false)
    bothLocales(state.labelKey)
    bothLocales(state.tooltipKey)
  })

  it("becomes an update once a version is installed", () => {
    const state = singBoxInstallButton(
      capability({ installed_version: "1.12.0", operation: "replace" }),
      false,
      false
    )
    expect(state.action).toBe("update")
    expect(state.enabled).toBe(true)
    expect(state.labelKey).toBe("transports.singBoxInstall.actionUpdate")
    bothLocales(state.tooltipKey)
  })

  it("goes quiet but stays visible when there is nothing to update", () => {
    // Disabled rather than hidden: a control that vanishes leaves the operator
    // wondering whether it ever existed, and the tooltip is what tells them
    // the version they have is the right one.
    const state = singBoxInstallButton(
      capability({
        installed_version: "1.13.14",
        operation: "reinstall_same_version",
      }),
      false,
      false
    )
    expect(state.enabled).toBe(false)
    expect(state.tooltipKey).toBe("transports.singBoxInstall.tipUpToDate")
    bothLocales(state.tooltipKey)
  })

  it("always has a tooltip, including in every disabled state", () => {
    // A disabled control with no explanation reads as broken, and the reason
    // it is disabled is exactly what the operator needs.
    const states = [
      singBoxInstallButton(undefined, false, false),
      singBoxInstallButton(capability(), true, false),
      singBoxInstallButton(capability(), false, true),
      singBoxInstallButton(
        capability({ available: false, blockers: ["entware_absent"] }),
        false,
        false
      ),
      singBoxInstallButton(
        capability({
          installed_version: "1.13.14",
          operation: "reinstall_same_version",
        }),
        false,
        false
      ),
    ]
    for (const state of states) {
      expect(state.enabled).toBe(false)
      expect(state.tooltipKey.length).toBeGreaterThan(0)
      bothLocales(state.tooltipKey)
    }
  })

  it("asks before it stops anything", () => {
    // Running transports are the one blocker an operator can answer, and the
    // button says so in the tooltip before they press it.
    const state = singBoxInstallButton(
      capability({
        available: false,
        blockers: ["transports_running"],
        installed_version: "1.12.0",
        running_transports: 2,
      }),
      false,
      false
    )
    expect(state.enabled).toBe(true)
    expect(state.needsConsent).toBe(true)
    expect(state.tooltipKey).toBe(
      "transports.singBoxInstall.tipWillStopTunnels"
    )
    bothLocales(state.tooltipKey)
  })

  it("never treats another blocker as consentable", () => {
    // Stopping the tunnels would achieve nothing, so asking would be a
    // question whose only honest answer is no.
    expect(
      singBoxInstallNeedsTransportConsent(
        capability({
          available: false,
          blockers: ["transports_running", "entware_absent"],
        })
      )
    ).toBe(false)
    expect(
      singBoxInstallNeedsTransportConsent(
        capability({ available: false, blockers: ["target_not_writable"] })
      )
    ).toBe(false)
    // Nothing blocking is not a case for consent either.
    expect(singBoxInstallNeedsTransportConsent(capability())).toBe(false)
    expect(singBoxInstallNeedsTransportConsent(undefined)).toBe(false)
  })
})

describe("sing-box install messages", () => {
  it("names every blocker, operation, outcome and verdict in both locales", () => {
    for (const blocker of Object.values(SingBoxInstallCapabilityBlockersItem)) {
      bothLocales(singBoxInstallBlockerKey(blocker))
    }
    for (const outcome of Object.values(SingBoxInstallResultInstallOutcome)) {
      bothLocales(singBoxInstallOutcomeKey(outcome))
    }
    for (const verdict of Object.values(SingBoxInstallResultReleaseVerdict)) {
      bothLocales(`transports.singBoxInstall.verdict.${verdict}`)
    }
  })

  it("names every phase the daemon emits, in both locales", () => {
    // The spellings are duplicated here on purpose: this is the seam where the
    // two sides can drift, and the C++ side pins the same list in
    // test_sing_box_installer.cpp.
    for (const phase of [
      "reading_release",
      "downloading_archive",
      "downloading_checksums",
      "verifying_archive",
      "unpacking",
      "checking_staged_version",
      "installing",
      "recording_marker",
    ]) {
      const key = singBoxInstallPhaseKey(phase)
      expect(key, phase).not.toBeNull()
      bothLocales(key as string)
    }
  })

  it("renders an unknown phase as nothing rather than as its raw name", () => {
    expect(singBoxInstallPhaseKey("teleporting")).toBeNull()
    expect(singBoxInstallPhaseKey("")).toBeNull()
  })

  it("calls a missing marker neither success nor failure", () => {
    expect(singBoxInstallResultTone("installed")).toBe("success")
    expect(singBoxInstallResultTone("marker_not_written")).toBe("warning")
    expect(singBoxInstallResultTone("install_failed")).toBe("failure")
  })

  it("shows a verdict only where one was actually reached", () => {
    expect(
      singBoxInstallVerdictKey({
        install_outcome: "release_refused",
        pinned_version: "1.13.14",
        release_verdict: "checksums_missing",
      })
    ).toBe("transports.singBoxInstall.verdict.checksums_missing")
    // A download that never happened produced no judgement about the release.
    expect(
      singBoxInstallVerdictKey({
        install_outcome: "download_failed",
        pinned_version: "1.13.14",
        release_verdict: "ready",
      })
    ).toBeNull()
  })

  it("shows the staged version only where it explains the outcome", () => {
    expect(
      singBoxInstallStagedVersion({
        install_outcome: "staged_version_mismatch",
        pinned_version: "1.13.14",
        staged_version: "1.12.0",
      })
    ).toBe("1.12.0")
    expect(
      singBoxInstallStagedVersion({
        install_outcome: "installed",
        pinned_version: "1.13.14",
        staged_version: "1.13.14",
      })
    ).toBeNull()
  })

  it("names the transports that did not come back", () => {
    // Their traffic has nowhere to go and only the operator can put it back,
    // so the tags are reported rather than summarised as a count.
    expect(
      singBoxInstallLeftDown({
        install_outcome: "installed",
        pinned_version: "1.13.14",
        transports_left_down: ["nl", "de"],
      } as never)
    ).toEqual(["nl", "de"])
    expect(
      singBoxInstallLeftDown({
        install_outcome: "installed",
        pinned_version: "1.13.14",
      })
    ).toEqual([])
    bothLocales("transports.singBoxInstall.leftDown")
  })

  it("only claims an install never started when it provably did not", () => {
    expect(singBoxInstallFailureTitleKey(2)).toBe(
      "transports.singBoxInstall.requestRefused"
    )
    expect(singBoxInstallFailureTitleKey(0)).toBe(
      "transports.singBoxInstall.requestFailed"
    )
    bothLocales("transports.singBoxInstall.requestRefused")
    bothLocales("transports.singBoxInstall.requestFailed")
  })

  it("warns the binary may have changed only when the install was under way", () => {
    expect(singBoxInstallMayHaveApplied(0, "aborted")).toBe(true)
    expect(singBoxInstallMayHaveApplied(0, null)).toBe(false)
    expect(singBoxInstallMayHaveApplied(0, "installed")).toBe(false)
    expect(singBoxInstallMayHaveApplied(1, "aborted")).toBe(false)
  })

  it("filters both sources of blockers with the same rule", () => {
    expect(
      singBoxInstallDisplayableBlockers([
        "entware_absent",
        "moon_phase_wrong",
        42,
      ])
    ).toEqual(["entware_absent"])
    expect(
      singBoxInstallRefusedBlockers({
        reason: "install_unavailable",
        blockers: ["transports_running", "moon_phase_wrong"],
      })
    ).toEqual(["transports_running"])
    expect(singBoxInstallRefusedBlockers({ blockers: ["entware_absent"] })).toEqual(
      []
    )
  })

  it("has copy for the wizard offer and the consent dialog", () => {
    for (const key of [
      "transports.singBoxInstall.setupTitle",
      "transports.singBoxInstall.setupBody",
      "transports.singBoxInstall.consentTitle",
      "transports.singBoxInstall.consentBody",
      "transports.singBoxInstall.consentConfirm",
      "transports.singBoxInstall.mayHaveApplied",
      "transports.singBoxInstall.stagedVersion",
      "transports.singBoxInstall.runningPlain",
    ]) {
      bothLocales(key)
    }
  })
})

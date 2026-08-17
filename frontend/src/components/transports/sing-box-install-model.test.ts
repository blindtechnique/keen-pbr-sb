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
  singBoxInstallButtonState,
  singBoxInstallFailureTitleKey,
  singBoxInstallMayHaveApplied,
  singBoxInstallOperationKey,
  singBoxInstallOutcomeKey,
  singBoxInstallPhaseKey,
  singBoxInstallRefusedBlockers,
  singBoxInstallResultTone,
  singBoxInstallStagedVersion,
  singBoxInstallUnmetPromiseKeys,
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

describe("sing-box install model", () => {
  // The daemon can report any of these, and a key that resolves to nothing
  // prints itself. Asserted against both dictionaries rather than one: a
  // Russian operator hitting an untranslated key is the same defect.
  it("names every blocker the API can report, in both locales", () => {
    for (const blocker of Object.values(SingBoxInstallCapabilityBlockersItem)) {
      const key = singBoxInstallBlockerKey(blocker)
      expect(lookup(enTranslation, key), key).toBeTypeOf("string")
      expect(lookup(ruTranslation, key), key).toBeTypeOf("string")
    }
  })

  it("names every operation and outcome the API can report", () => {
    for (const operation of Object.values(SingBoxInstallCapabilityOperation)) {
      const key = singBoxInstallOperationKey(operation)
      expect(lookup(enTranslation, key), key).toBeTypeOf("string")
      expect(lookup(ruTranslation, key), key).toBeTypeOf("string")
    }
    for (const outcome of Object.values(SingBoxInstallResultInstallOutcome)) {
      const key = singBoxInstallOutcomeKey(outcome)
      expect(lookup(enTranslation, key), key).toBeTypeOf("string")
      expect(lookup(ruTranslation, key), key).toBeTypeOf("string")
    }
    for (const verdict of Object.values(SingBoxInstallResultReleaseVerdict)) {
      const key = `transports.singBoxInstall.verdict.${verdict}`
      expect(lookup(enTranslation, key), key).toBeTypeOf("string")
      expect(lookup(ruTranslation, key), key).toBeTypeOf("string")
    }
  })

  // Every phase name the daemon's installer can emit. The list is duplicated
  // here on purpose: this is the seam where the two sides can drift, and the
  // C++ side pins the same spellings in test_sing_box_installer.cpp.
  it("names every phase the daemon emits, in both locales", () => {
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
      expect(lookup(enTranslation, key as string), phase).toBeTypeOf("string")
      expect(lookup(ruTranslation, key as string), phase).toBeTypeOf("string")
    }
  })

  it("renders an unknown phase as nothing rather than as its raw name", () => {
    // A step from a newer daemon is not an explanation to show an operator;
    // the card falls back to the plain running text.
    expect(singBoxInstallPhaseKey("teleporting")).toBeNull()
    expect(singBoxInstallPhaseKey("")).toBeNull()
  })

  it("calls a missing marker neither success nor failure", () => {
    // The binary is in place and correct. Calling it a failure tells an
    // operator to retry something that worked; calling it a success hides
    // that the next capability read will refuse to touch the binary.
    expect(singBoxInstallResultTone("installed")).toBe("success")
    expect(singBoxInstallResultTone("marker_not_written")).toBe("warning")
    expect(singBoxInstallResultTone("install_failed")).toBe("failure")
    expect(singBoxInstallResultTone("checksum_mismatch")).toBe("failure")
  })

  it("shows a verdict only where one was actually reached", () => {
    expect(
      singBoxInstallVerdictKey({
        install_outcome: "release_refused",
        pinned_version: "1.13.14",
        release_verdict: "checksums_missing",
      })
    ).toBe("transports.singBoxInstall.verdict.checksums_missing")
    expect(
      singBoxInstallVerdictKey({
        install_outcome: "checksum_mismatch",
        pinned_version: "1.13.14",
        release_verdict: "checksum_unusable",
      })
    ).toBe("transports.singBoxInstall.verdict.checksum_unusable")
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
    // After a success it is the same number as the pin, and printing it
    // invites the reading that something unexpected was installed.
    expect(
      singBoxInstallStagedVersion({
        install_outcome: "installed",
        pinned_version: "1.13.14",
        staged_version: "1.13.14",
      })
    ).toBeNull()
  })

  it("keeps the button disabled while an install is running elsewhere", () => {
    // The stream is the authority, not this tab's mutation state: the daemon
    // does not stop installing because a tab closed, and a second tab must
    // not be able to start another.
    const state = singBoxInstallButtonState(capability(), true, false)
    expect(state.enabled).toBe(false)
    expect(state.disabledReasonKey).toBe("transports.singBoxInstall.running")
  })

  it("enables the button only when the capability says it may", () => {
    expect(singBoxInstallButtonState(capability(), false, false).enabled).toBe(
      true
    )
    expect(
      singBoxInstallButtonState(
        capability({ available: false, blockers: ["transports_running"] }),
        false,
        false
      ).enabled
    ).toBe(false)
    // Nothing measured yet is not permission.
    expect(
      singBoxInstallButtonState(undefined, false, false).enabled
    ).toBe(false)
  })

  it("takes the refusal's blockers as the newer truth", () => {
    // The install re-measures before doing anything, so an operator who
    // started a tunnel after the capability was read is told about it here.
    expect(
      singBoxInstallRefusedBlockers({
        reason: "install_unavailable",
        blockers: ["transports_running", "target_not_writable"],
      })
    ).toEqual(["transports_running", "target_not_writable"])
  })

  it("drops a blocker name this build does not know", () => {
    // It would otherwise reach t() as a key that resolves to nothing and
    // print itself at the operator.
    expect(
      singBoxInstallRefusedBlockers({
        reason: "install_unavailable",
        blockers: ["transports_running", "moon_phase_wrong", 7, null],
      })
    ).toEqual(["transports_running"])
  })

  it("ignores an error body that is not a refusal", () => {
    expect(singBoxInstallRefusedBlockers(undefined)).toEqual([])
    expect(singBoxInstallRefusedBlockers("nope")).toEqual([])
    expect(
      singBoxInstallRefusedBlockers({ blockers: ["transports_running"] })
    ).toEqual([])
    expect(
      singBoxInstallRefusedBlockers({
        reason: "maintenance_busy",
        blockers: ["transports_running"],
      })
    ).toEqual([])
  })

  it("only claims an install never started when it provably did not", () => {
    // The daemon emits the blocker body exclusively from the capability
    // re-check, before the lease and before any work, so blockers prove
    // nothing was attempted.
    expect(singBoxInstallFailureTitleKey(2)).toBe(
      "transports.singBoxInstall.requestRefused"
    )
    // Everything else can have failed at any point - including after the swap,
    // because the daemon verifies it still holds the lease AFTER replacing the
    // binary. "Did not start" there would leave an operator believing their
    // transports still run the old binary.
    expect(singBoxInstallFailureTitleKey(0)).toBe(
      "transports.singBoxInstall.requestFailed"
    )
  })

  it("warns the binary may have changed only when the install was under way", () => {
    // `aborted` is what the daemon publishes when the request died with the
    // install already running - the only ending that does not come back in a
    // response body.
    expect(singBoxInstallMayHaveApplied(0, "aborted")).toBe(true)
    // Nothing ended, or it ended by naming a real outcome: no warning.
    expect(singBoxInstallMayHaveApplied(0, null)).toBe(false)
    expect(singBoxInstallMayHaveApplied(0, "installed")).toBe(false)
    expect(singBoxInstallMayHaveApplied(0, "download_failed")).toBe(false)
    // A refusal that named blockers never began, whatever the stream says.
    expect(singBoxInstallMayHaveApplied(1, "aborted")).toBe(false)
  })

  it("advertises exactly the promises this build does not keep", () => {
    expect(singBoxInstallUnmetPromiseKeys(capability())).toEqual([
      "transports.singBoxInstall.promiseSignature",
      "transports.singBoxInstall.promiseRollback",
    ])
    // Read from the capability, so a build that starts keeping one stops
    // advertising the gap without anybody editing the card.
    expect(
      singBoxInstallUnmetPromiseKeys(
        capability({ signed_release: true, exact_rollback: true })
      )
    ).toEqual([])
    expect(
      singBoxInstallUnmetPromiseKeys(
        capability({ verified_archive_checksum: false })
      )
    ).toContain("transports.singBoxInstall.promiseChecksum")
  })
})

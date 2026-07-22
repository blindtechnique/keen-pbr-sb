import { describe, expect, test } from "bun:test"

import { getSoftwareUpdateDialogContent } from "@/components/settings/software-update-view"

describe("software update dialog content", () => {
  test("shows release notes before an update starts", () => {
    expect(getSoftwareUpdateDialogContent({ running: false }, false)).toBe(
      "release-notes"
    )
  })

  test("replaces release notes as soon as the update attempt starts", () => {
    expect(getSoftwareUpdateDialogContent({ running: false }, true)).toBe(
      "update-log"
    )
  })

  test("keeps the update log visible while the backend is running", () => {
    expect(getSoftwareUpdateDialogContent({ running: true }, false)).toBe(
      "update-log"
    )
  })
})

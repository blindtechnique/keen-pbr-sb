import { describe, expect, test } from "bun:test"

import { transportErrorText } from "@/components/transports/transport-error-model"

describe("transport error text", () => {
  test("the reported message loses its component name and gains a reason", () => {
    // Verbatim from the router.
    const raw =
      "keen-pbr routing health: degraded: HTTP request failed: Connection timed out after 5002 milliseconds."
    expect(transportErrorText(raw)).toEqual({
      kind: "issue",
      code: "probeTimeout",
    })
  })

  test("an unrecognised detail still names the state rather than vanishing", () => {
    expect(
      transportErrorText("keen-pbr routing health: degraded: something new")
    ).toEqual({ kind: "issue", code: "degraded" })
  })

  test("other failures are passed through untouched", () => {
    // Not the supervisor's line. Classifying it would put words in the
    // daemon's mouth; dropping it would lose the only report there is.
    const raw = "sing-box exited with status 1"
    expect(transportErrorText(raw)).toEqual({ kind: "raw", text: raw })
  })

  test("nothing is rendered for an absent or blank error", () => {
    expect(transportErrorText(undefined)).toBeNull()
    expect(transportErrorText("   ")).toBeNull()
  })

  test("a prefix with no detail still classifies from the verdict", () => {
    expect(transportErrorText("keen-pbr routing health: degraded")).toEqual({
      kind: "issue",
      code: "degraded",
    })
  })

  test("a refused connection is named as such", () => {
    expect(
      transportErrorText(
        "keen-pbr routing health: degraded: HTTP request failed: Connection refused"
      )
    ).toEqual({ kind: "issue", code: "connectionRefused" })
  })
})

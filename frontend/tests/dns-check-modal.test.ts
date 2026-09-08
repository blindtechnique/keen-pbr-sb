import { readFileSync } from "node:fs"

import { describe, expect, test } from "bun:test"

const source = readFileSync(
  new URL("../src/components/overview/dns-check-modal.tsx", import.meta.url),
  "utf8"
)

describe("DNS check modal presentation", () => {
  test("unconfirmed browser status is not a red DNS failure", () => {
    expect(source).not.toContain("text-destructive")
    expect(source).toContain("text-warning-foreground")
    expect(source).toContain("text-muted-foreground")
    expect(source).toContain("isPcSuccess && !isBrowserSuccess")
    expect(source).toContain("overview.dnsCheck.modal.browserUnconfirmed")
  })

  test("manual stream failure has its own explanation before the waiting state", () => {
    const manualStatus = source.slice(source.indexOf("function getPcStatusText("))
    expect(manualStatus).toContain('status === "sse-fail"')
    expect(manualStatus).toContain("overview.dnsCheck.status.sseUnavailable")
    expect(manualStatus.indexOf('status === "sse-fail"')).toBeLessThan(
      manualStatus.indexOf("if (isWaiting)")
    )
  })

  test("an expired observation offers a new probe only through an explicit click", () => {
    expect(source).toContain(
      "const hasExpired = !pcCheckState.waiting && pcCheckState.showWarning"
    )
    expect(source).toContain("overview.dnsCheck.modal.expired")
    expect(source).toContain('hasExpired || pcStatus === "sse-fail"')
    expect(source).toContain("onClick={() => startPcCheck(false)}")
    // One initial start on opening and one user-triggered retry; no timer retry.
    expect(source.match(/startPcCheck\(false\)/g)).toHaveLength(2)
    expect(source).toContain("pcCheckState.waiting && command")
  })

  test("closing or unmounting resets the probe and command copying is retained", () => {
    expect(source).toContain("return resetPcCheck")
    expect(source).toContain("[open, resetPcCheck, startPcCheck]")
    expect(source).toContain("event.currentTarget.select()")
    expect(source).toContain("void copyCommand(command, setCopyFeedback)")
    expect(source).toContain("window.clearTimeout(resetTimerRef.current)")
  })
})

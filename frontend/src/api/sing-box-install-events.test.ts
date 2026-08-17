import { readFileSync } from "node:fs"
import { join } from "node:path"

import { beforeEach, describe, expect, it } from "bun:test"

import {
  applySingBoxInstallStatusEvent,
  getSingBoxInstallProgress,
  resetSingBoxInstallProgress,
  subscribeSingBoxInstall,
} from "@/api/sing-box-install-events"

function frame(data: Record<string, unknown>) {
  return JSON.stringify({ type: "sing_box_install", data })
}

describe("sing-box install status events", () => {
  beforeEach(() => {
    resetSingBoxInstallProgress()
  })

  it("keeps the phase the daemon is on", () => {
    expect(
      applySingBoxInstallStatusEvent(
        frame({
          phase: "downloading_archive",
          active: true,
          pinned_version: "1.13.14",
          outcome: "",
        })
      )
    ).toBe(true)
    expect(getSingBoxInstallProgress()?.phase).toBe("downloading_archive")
    expect(getSingBoxInstallProgress()?.pinnedVersion).toBe("1.13.14")
  })

  it("stops being progress once the install ends", () => {
    applySingBoxInstallStatusEvent(
      frame({ phase: "installing", active: true, outcome: "" })
    )
    applySingBoxInstallStatusEvent(
      frame({ phase: "finished", active: false, outcome: "installed" })
    )
    // Otherwise the card would sit on "finished" forever and never offer the
    // button again.
    expect(getSingBoxInstallProgress()).toBeNull()
  })

  it("treats an aborted install as ended", () => {
    // The daemon publishes this when the request died before it could report
    // an outcome - a lost maintenance lease, a throw. The install may well
    // have happened; what is certain is that nothing is watching it any more.
    applySingBoxInstallStatusEvent(
      frame({ phase: "unpacking", active: true, outcome: "" })
    )
    applySingBoxInstallStatusEvent(
      frame({ phase: "finished", active: false, outcome: "aborted" })
    )
    expect(getSingBoxInstallProgress()).toBeNull()
  })

  it("refuses a frame that is not shaped like one", () => {
    expect(applySingBoxInstallStatusEvent("{")).toBe(false)
    expect(applySingBoxInstallStatusEvent(JSON.stringify({ type: "x" }))).toBe(
      false
    )
    // A frame missing the fields the card renders is ignored rather than
    // rendered as a step whose name this page invented.
    expect(applySingBoxInstallStatusEvent(frame({ active: true }))).toBe(false)
    expect(
      applySingBoxInstallStatusEvent(frame({ phase: "unpacking" }))
    ).toBe(false)
    expect(getSingBoxInstallProgress()).toBeNull()
  })

  it("does not claim to have handled another feature's frame", () => {
    // The bridge routes by event name, but the envelope carries the type too,
    // and a parser that accepted anything would make the two disagree.
    expect(
      applySingBoxInstallStatusEvent(
        JSON.stringify({
          type: "component_transaction",
          data: { phase: "installing", active: true },
        })
      )
    ).toBe(false)
  })

  it("replays the current state to a component that mounts late", () => {
    applySingBoxInstallStatusEvent(
      frame({ phase: "verifying_archive", active: true, outcome: "" })
    )
    let seen: string | null | undefined
    const stop = subscribeSingBoxInstall((progress) => {
      seen = progress ? progress.phase : null
    })
    // The stream replays its last frame to a new EventSource, but a card
    // mounted after that frame arrived would otherwise never see it.
    expect(seen).toBe("verifying_archive")
    stop()
  })

  // Everything above tests the parser, and the parser is only reachable if the
  // bridge subscribes to the event by name. Nothing else in this file would
  // notice that it does not: the feature would pass every test and be inert in
  // production, which is the failure this repository has already been bitten
  // by twice (a handler declared but never called).
  //
  // Read from the source rather than exercised through an EventSource, which
  // is the same trade component-transaction-events.test.ts makes.
  //
  // The subscription list is located and searched on its own, not the whole
  // file: the first version of this test asserted the file merely contained
  // the string, which the dispatch branch below satisfies by itself. Deleting
  // the list entry - the edit that makes the feature inert - left it green.
  it("is named in the bridge's subscription list, not just mentioned", () => {
    const bridge = readFileSync(
      join(import.meta.dir, "status-event-bridge.tsx"),
      "utf8"
    )
    const start = bridge.indexOf("const STATUS_EVENT_NAMES = [")
    expect(start).toBeGreaterThanOrEqual(0)
    const end = bridge.indexOf("]", start)
    expect(end).toBeGreaterThan(start)
    const subscribedNames = bridge.slice(start, end)

    expect(subscribedNames).toContain('"sing_box_install"')
  })

  it("is routed to this module by the bridge", () => {
    const bridge = readFileSync(
      join(import.meta.dir, "status-event-bridge.tsx"),
      "utf8"
    )
    // Subscribing without dispatching would be just as inert as the reverse.
    expect(bridge).toContain('eventName === "sing_box_install"')
    expect(bridge).toContain("applySingBoxInstallStatusEvent(data)")
  })

  it("stops notifying a component that unsubscribed", () => {
    let calls = 0
    const stop = subscribeSingBoxInstall(() => {
      calls += 1
    })
    expect(calls).toBe(1)
    stop()
    applySingBoxInstallStatusEvent(
      frame({ phase: "installing", active: true, outcome: "" })
    )
    expect(calls).toBe(1)
  })
})

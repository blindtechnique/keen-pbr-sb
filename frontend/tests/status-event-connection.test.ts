import { describe, expect, test } from "bun:test"

import {
  acquireStatusEventKeepAliveLease,
  hasStatusEventKeepAliveLease,
  subscribeStatusEventKeepAliveLease,
} from "../src/api/status-event-connection"

describe("status event connection keep-alive leases", () => {
  test("keeps the shared stream alive until every active operation releases", () => {
    let changes = 0
    const unsubscribe = subscribeStatusEventKeepAliveLease(() => {
      changes += 1
    })
    const releaseFirst = acquireStatusEventKeepAliveLease()
    const releaseSecond = acquireStatusEventKeepAliveLease()

    expect(hasStatusEventKeepAliveLease()).toBe(true)
    releaseFirst()
    expect(hasStatusEventKeepAliveLease()).toBe(true)
    releaseSecond()
    expect(hasStatusEventKeepAliveLease()).toBe(false)

    // Releasing twice is harmless and does not notify observers again.
    releaseSecond()
    expect(changes).toBe(4)
    unsubscribe()
  })
})

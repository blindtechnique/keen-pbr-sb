import { describe, expect, test } from "bun:test"

import {
  fetchUpdateCommand,
  startUpdatePolling,
  UpdateRequestTimeout,
} from "../src/components/settings/software-update-polling"
import {
  fetchWithStepUp,
  resetStepUpState,
  setStepUpPrompt,
  type StepUpCredentials,
} from "../src/lib/step-up"

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason: unknown) => void
  const promise = new Promise<T>((yes, no) => {
    resolve = yes
    reject = no
  })
  return { promise, resolve, reject }
}

async function flushPromises() {
  // Includes read -> Promise.race -> callback -> finally scheduling.
  for (let turn = 0; turn < 16; turn++) await Promise.resolve()
}

class ManualClock {
  time = 1000
  private nextId = 1
  private jobs = new Map<number, { at: number; run: () => void }>()

  get pending() {
    return this.jobs.size
  }

  set = (
    callback: (...args: unknown[]) => void,
    delay = 0,
    ...args: unknown[]
  ) => {
    const id = this.nextId++
    this.jobs.set(id, { at: this.time + delay, run: () => callback(...args) })
    return id
  }

  clear = (id: unknown) => {
    this.jobs.delete(Number(id))
  }

  async advance(milliseconds: number) {
    const target = this.time + milliseconds
    for (let budget = 0; budget < 1000; budget++) {
      const next = [...this.jobs.entries()]
        .filter(([, job]) => job.at <= target)
        .sort((a, b) => a[1].at - b[1].at || a[0] - b[0])[0]
      if (!next) {
        this.time = target
        await flushPromises()
        return
      }
      this.time = next[1].at
      this.jobs.delete(next[0])
      next[1].run()
      await flushPromises()
    }
    throw new Error("polling scheduled an unbounded timer loop")
  }
}

async function withClock(run: (clock: ManualClock) => Promise<void>) {
  const originalSet = globalThis.setTimeout
  const originalClear = globalThis.clearTimeout
  const clock = new ManualClock()
  globalThis.setTimeout = clock.set as unknown as typeof setTimeout
  globalThis.clearTimeout = clock.clear as typeof clearTimeout
  try {
    await run(clock)
  } finally {
    globalThis.setTimeout = originalSet
    globalThis.clearTimeout = originalClear
  }
}

describe("software update sequential status polling", () => {
  test("waits for one read to finish, then waits the interval before the next", async () => {
    await withClock(async (clock) => {
      const reads: ReturnType<typeof deferred<number>>[] = []
      const values: number[] = []
      const stop = startUpdatePolling({
        read: () => {
          const request = deferred<number>()
          reads.push(request)
          return request.promise
        },
        onValue: (value) => {
          values.push(value)
        },
        onError: () => {
          throw new Error("unexpected poll error")
        },
        onExpired: () => {
          throw new Error("unexpected expiry")
        },
        deadline: clock.time + 1000,
        now: () => clock.time,
        intervalMs: 10,
        timeoutMs: 100,
      })
      expect(reads).toHaveLength(1)
      await clock.advance(50)
      expect(reads).toHaveLength(1)
      reads[0]!.resolve(7)
      await flushPromises()
      expect(values).toEqual([7])
      await clock.advance(9)
      expect(reads).toHaveLength(1)
      await clock.advance(1)
      expect(reads).toHaveLength(2)
      stop()
      expect(clock.pending).toBe(0)
    })
  })

  test("times out and aborts one read before scheduling the next read", async () => {
    await withClock(async (clock) => {
      const signals: AbortSignal[] = []
      const errors: unknown[] = []
      const stop = startUpdatePolling({
        read: (signal) => {
          signals.push(signal)
          return new Promise<never>(() => {})
        },
        onValue: () => {
          throw new Error("unexpected value")
        },
        onError: (error) => {
          errors.push(error)
        },
        onExpired: () => {},
        deadline: clock.time + 1000,
        now: () => clock.time,
        intervalMs: 10,
        timeoutMs: 20,
      })
      await clock.advance(20)
      expect(signals).toHaveLength(1)
      expect(signals[0]!.aborted).toBe(true)
      expect(errors).toHaveLength(1)
      expect(errors[0]).toBeInstanceOf(UpdateRequestTimeout)
      await clock.advance(9)
      expect(signals).toHaveLength(1)
      await clock.advance(1)
      expect(signals).toHaveLength(2)
      stop()
      expect(signals[1]!.aborted).toBe(true)
      expect(clock.pending).toBe(0)
    })
  })

  test.each(["value", "error"] as const)(
    "stop clears the active timeout immediately and suppresses a late %s",
    async (outcome) => {
      await withClock(async (clock) => {
        const request = deferred<number>()
        const published: unknown[] = []
        let reads = 0
        let signal!: AbortSignal
        const stop = startUpdatePolling({
          read: (current) => {
            reads++
            signal = current
            return request.promise
          },
          onValue: (value) => {
            published.push(value)
          },
          onError: (error) => {
            published.push(error)
          },
          onExpired: () => {
            published.push("expired")
          },
          deadline: clock.time + 50,
          now: () => clock.time,
          intervalMs: 10,
          timeoutMs: 20,
        })
        expect(clock.pending).toBe(1)
        stop()
        stop() // Disposal is safe when both React cleanup and completion call it.
        expect(signal.aborted).toBe(true)
        expect(clock.pending).toBe(0)
        if (outcome === "value") request.resolve(17)
        else request.reject(new Error("late network failure"))
        await flushPromises()
        await clock.advance(100)
        expect(published).toEqual([])
        expect(reads).toBe(1)
        expect(clock.pending).toBe(0)
      })
    }
  )

  test("expires once without starting a request after the polling deadline", async () => {
    await withClock(async (clock) => {
      let reads = 0
      let expired = 0
      startUpdatePolling({
        read: async () => ++reads,
        onValue: () => {},
        onError: () => {
          throw new Error("unexpected poll error")
        },
        onExpired: () => {
          expired++
        },
        deadline: clock.time + 15,
        now: () => clock.time,
        intervalMs: 10,
        timeoutMs: 20,
      })
      await flushPromises()
      await clock.advance(20)
      expect(reads).toBe(2)
      expect(expired).toBe(1)
      expect(clock.pending).toBe(0)
      await clock.advance(100)
      expect(reads).toBe(2)
      expect(expired).toBe(1)
    })
  })

  test("an already expired session performs no read", async () => {
    await withClock(async (clock) => {
      let reads = 0
      let expired = 0
      startUpdatePolling({
        read: async () => ++reads,
        onValue: () => {},
        onError: () => {},
        onExpired: () => {
          expired++
        },
        deadline: clock.time,
        now: () => clock.time,
      })
      expect(reads).toBe(0)
      expect(expired).toBe(1)
      expect(clock.pending).toBe(0)
    })
  })

  test("onValue false disposes polling without a later value or expiry", async () => {
    await withClock(async (clock) => {
      let reads = 0
      let values = 0
      let expired = 0
      startUpdatePolling({
        read: async () => ++reads,
        onValue: () => {
          values++
          return false
        },
        onError: () => {
          throw new Error("unexpected poll error")
        },
        onExpired: () => {
          expired++
        },
        deadline: clock.time + 15,
        now: () => clock.time,
        intervalMs: 10,
        timeoutMs: 20,
      })
      await flushPromises()
      expect(clock.pending).toBe(0)
      await clock.advance(100)
      expect(reads).toBe(1)
      expect(values).toBe(1)
      expect(expired).toBe(0)
    })
  })
})

describe("software update command HTTP deadline", () => {
  test("step-up prompt time is not limited by the HTTP deadline and only a refused POST is replayed", async () => {
    resetStepUpState()
    try {
      await withClock(async (clock) => {
        const prompt = deferred<StepUpCredentials | null>()
        let prompts = 0
        let settled = false
        const requests: string[] = []
        const signals: AbortSignal[] = []
        setStepUpPrompt(() => {
          prompts++
          return prompt.promise
        })
        const rawFetch = (async (input, init) => {
          const url = String(input)
          requests.push(url)
          signals.push(init!.signal!)
          if (requests.length === 1) {
            return new Response(JSON.stringify({ error: "step_up_required" }), {
              status: 403,
              headers: { "Content-Type": "application/json" },
            })
          }
          if (url === "/api/auth/step-up") {
            return new Response(JSON.stringify({ ok: true }), { status: 200 })
          }
          return new Response(JSON.stringify({ ok: true, started: true }), {
            status: 200,
          })
        }) as typeof fetch
        const result = fetchWithStepUp(
          "/api/system/update",
          { method: "POST" },
          (input, init) => fetchUpdateCommand(input, init, rawFetch, 20)
        ).then((response) => {
          settled = true
          return response
        })
        await flushPromises()
        expect(prompts).toBe(1)
        expect(requests).toEqual(["/api/system/update"])
        expect(clock.pending).toBe(0)
        await clock.advance(100)
        expect(settled).toBe(false)
        expect(requests).toHaveLength(1)
        prompt.resolve({ username: "test-user", password: "test-only" })
        const response = await result
        expect(response.status).toBe(200)
        expect(await response.json()).toEqual({ ok: true, started: true })
        expect(requests).toEqual([
          "/api/system/update",
          "/api/auth/step-up",
          "/api/system/update",
        ])
        expect(prompts).toBe(1)
        expect(signals.every((signal) => !signal.aborted)).toBe(true)
        expect(clock.pending).toBe(0)
      })
    } finally {
      resetStepUpState()
    }
  })

  test.each(["headers", "body"] as const)(
    "bounds waiting for %s, aborts, and never resends the POST",
    async (stage) => {
      await withClock(async (clock) => {
        let requests = 0
        let signal!: AbortSignal
        const fetchImpl = (async (_input, init) => {
          requests++
          signal = init!.signal!
          if (stage === "headers") return new Promise<Response>(() => {})
          return {
            arrayBuffer: () => new Promise<ArrayBuffer>(() => {}),
          } as Response
        }) as typeof fetch
        const result = fetchUpdateCommand(
          "/api/system/update",
          { method: "POST" },
          fetchImpl,
          20
        ).then(
          () => "unexpected success",
          (error) => error
        )
        await flushPromises()
        await clock.advance(20)
        expect(await result).toBeInstanceOf(UpdateRequestTimeout)
        expect(signal.aborted).toBe(true)
        expect(requests).toBe(1)
        expect(clock.pending).toBe(0)
        await clock.advance(100)
        expect(requests).toBe(1)
      })
    }
  )

  test("preserves a 401 body, status and headers instead of turning it into success", async () => {
    await withClock(async (clock) => {
      const body = JSON.stringify({ error: "reauthentication_required" })
      let calls = 0
      let sentInit: RequestInit | undefined
      const response = await fetchUpdateCommand(
        "/api/system/update",
        {
          method: "POST",
          credentials: "same-origin",
          headers: { "X-Request": "update" },
        },
        (async (_input, init) => {
          calls++
          sentInit = init
          return new Response(body, {
            status: 401,
            statusText: "Unauthorized",
            headers: {
              "Content-Type": "application/json",
              "X-Result": "auth-needed",
            },
          })
        }) as typeof fetch,
        20
      )
      expect(response.ok).toBe(false)
      expect(response.status).toBe(401)
      expect(response.statusText).toBe("Unauthorized")
      expect(response.headers.get("X-Result")).toBe("auth-needed")
      expect(response.headers.get("Content-Type")).toBe("application/json")
      expect(await response.text()).toBe(body)
      expect(sentInit?.method).toBe("POST")
      expect(sentInit?.credentials).toBe("same-origin")
      expect(sentInit?.headers).toEqual({ "X-Request": "update" })
      expect(calls).toBe(1)
      expect(clock.pending).toBe(0)
      await clock.advance(100)
      expect(calls).toBe(1)
    })
  })

  test("preserves a transport failure and clears its timer without a retry", async () => {
    await withClock(async (clock) => {
      const failure = new TypeError("connection closed")
      let calls = 0
      const result = fetchUpdateCommand(
        "/api/system/update",
        { method: "POST" },
        (async () => {
          calls++
          throw failure
        }) as typeof fetch,
        20
      ).then(
        () => "unexpected success",
        (error) => error
      )
      expect(await result).toBe(failure)
      expect(clock.pending).toBe(0)
      await clock.advance(100)
      expect(calls).toBe(1)
    })
  })
})

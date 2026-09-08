import { describe, expect, test } from "bun:test"
import { readFileSync } from "node:fs"
import { MutationObserver, QueryClient } from "@tanstack/react-query"

import { runSubscriptionPreviewRequest } from "../src/components/transports/subscription-preview-request"

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (error: Error) => void
  const promise = new Promise<T>((accept, refuse) => {
    resolve = accept
    reject = refuse
  })
  return { promise, resolve, reject }
}

function fixture() {
  const client = new QueryClient({
    defaultOptions: { mutations: { retry: false, gcTime: Infinity } },
  })
  const active = { current: null as symbol | null }
  const calls: string[] = []
  const shown: string[] = []
  const pending = new Map(
    ["old", "new", "duplicate"].map((source) => [
      source,
      { result: deferred<string>(), started: deferred<void>() },
    ])
  )
  const observer = new MutationObserver<string, Error, string>(client, {
    mutationFn: (source) => {
      calls.push(source)
      const request = pending.get(source)!
      request.started.resolve()
      return request.result.promise
    },
  })
  const unsubscribe = observer.subscribe(() => undefined)
  const start = (source: string) =>
    runSubscriptionPreviewRequest(
      active,
      () => observer.mutate(source),
      (response) => shown.push(response)
    )
  const reset = () => {
    active.current = null
    observer.reset()
  }
  const dispose = () => {
    active.current = null
    unsubscribe()
    client.clear()
  }
  return { active, calls, shown, pending, observer, start, reset, dispose }
}

describe("subscription preview request lifecycle", () => {
  for (const oldFinishesFirst of [true, false]) {
    test(`reset and reopen ignores an old success (${oldFinishesFirst ? "before" : "after"} the new response)`, async () => {
      const state = fixture()
      try {
        const old = state.start("old")
        await state.pending.get("old")!.started.promise
        state.reset()
        expect(state.observer.getCurrentResult().status).toBe("idle")

        const current = state.start("new")
        await state.pending.get("new")!.started.promise
        const currentToken = state.active.current
        expect(currentToken).not.toBeNull()
        if (oldFinishesFirst) {
          state.pending.get("old")!.result.resolve("discarded preview")
          await old
          expect(state.shown).toEqual([])
          expect(state.active.current).toBe(currentToken)
          expect(state.observer.getCurrentResult().status).toBe("pending")
        }

        state.pending.get("new")!.result.resolve("current preview")
        await current
        if (!oldFinishesFirst) {
          state.pending.get("old")!.result.resolve("discarded preview")
          await old
        }
        expect(state.calls).toEqual(["old", "new"])
        expect(state.shown).toEqual(["current preview"])
        expect(state.observer.getCurrentResult().data).toBe("current preview")
        expect(state.active.current).toBeNull()
      } finally {
        state.dispose()
      }
    })
  }

  test("a rejected dismissed request cannot replace the reopened form error", async () => {
    const state = fixture()
    try {
      const old = state.start("old")
      await state.pending.get("old")!.started.promise
      state.reset()
      const current = state.start("new")
      await state.pending.get("new")!.started.promise
      const currentToken = state.active.current

      state.pending.get("old")!.result.reject(new Error("old provider failed"))
      await old
      expect(state.observer.getCurrentResult().status).toBe("pending")
      expect(state.observer.getCurrentResult().error).toBeNull()
      expect(state.active.current).toBe(currentToken)
      expect(state.shown).toEqual([])
      state.pending.get("new")!.result.resolve("current preview")
      await current
      expect(state.shown).toEqual(["current preview"])
      expect(state.observer.getCurrentResult().error).toBeNull()
    } finally {
      state.dispose()
    }
  })

  test("an active failure remains visible and releases the request for retry", async () => {
    const state = fixture()
    try {
      const first = state.start("old")
      await state.pending.get("old")!.started.promise
      const failure = new Error("current provider failed")
      state.pending.get("old")!.result.reject(failure)
      await first
      expect(state.observer.getCurrentResult().error).toBe(failure)
      expect(state.active.current).toBeNull()

      const retry = state.start("new")
      await state.pending.get("new")!.started.promise
      state.pending.get("new")!.result.resolve("retry preview")
      await retry
      expect(state.shown).toEqual(["retry preview"])
      expect(state.active.current).toBeNull()
    } finally {
      state.dispose()
    }
  })

  test("a duplicate preview action does not replace the current request", async () => {
    const state = fixture()
    try {
      const current = state.start("new")
      await state.pending.get("new")!.started.promise
      const currentToken = state.active.current
      await state.start("duplicate")
      expect(state.calls).toEqual(["new"])
      expect(state.active.current).toBe(currentToken)
      state.pending.get("new")!.result.resolve("current preview")
      await current
      expect(state.shown).toEqual(["current preview"])
    } finally {
      state.dispose()
    }
  })

  test("direct dialog unmount discards a late preview without publishing", async () => {
    const state = fixture()
    const request = state.start("old")
    await state.pending.get("old")!.started.promise
    state.dispose()
    state.pending.get("old")!.result.resolve("unmounted preview")
    await request
    expect(state.shown).toEqual([])
    expect(state.active.current).toBeNull()
  })

  test("the dialog uses the tested promise path for seeded and manual previews", () => {
    const source = readFileSync(
      new URL(
        "../src/components/transports/subscription-import-dialog.tsx",
        import.meta.url
      ),
      "utf8"
    )
    expect(source).toContain("void runSubscriptionPreviewRequest(")
    expect(source).toContain("previewMutation.mutateAsync(")
    expect(source).not.toContain("previewInFlight")
    expect(source).not.toContain("previewMutation.mutate(")
    expect(source).toMatch(
      /const resetPreview = \(\) => \{\s*previewRequest.current = null\s*previewMutation.reset\(\)/
    )
    expect(source).toMatch(/const reset = \(\) => \{\s*resetPreview\(\)/)
    expect(source).toMatch(
      /resetPreview\(\)\s*if \(seed\) fetchPreview\(seed\)/
    )
    expect(source).toMatch(
      /useEffect\(\s*\(\) => \(\) => \{\s*previewRequest.current = null\s*\},\s*\[\]/
    )
    expect(source).toContain("source ?? { url: url.trim() }")
    expect(source).toContain("if (preview || previewMutation.isPending) return")
  })
})

import { describe, expect, test } from "bun:test"
import { readFileSync } from "node:fs"
import {
  MutationObserver,
  QueryClient,
  QueryObserver,
} from "@tanstack/react-query"
import {
  invalidateSubscriptionQueries,
  SUBSCRIPTION_CHANGE_QUERY_KEYS,
} from "@/api/subscription-events"

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason: Error) => void
  const promise = new Promise<T>((yes, no) => {
    resolve = yes
    reject = no
  })
  return { promise, resolve, reject }
}

describe("confirmed subscription import completion", () => {
  test.each(["success", "error"] as const)(
    "closes after POST while all refreshes remain pending, including later GET %s",
    async (refreshOutcome) => {
      const client = new QueryClient({
        defaultOptions: {
          queries: { retry: false },
          mutations: { retry: false },
        },
      })
      const reply = deferred<{ imported: number }>()
      const refreshes = SUBSCRIPTION_CHANGE_QUERY_KEYS.map(() =>
        deferred<{ refreshed: boolean }>()
      )
      const started: number[] = []
      const observers = SUBSCRIPTION_CHANGE_QUERY_KEYS.map(
        (queryKey, index) =>
          new QueryObserver(client, {
            queryKey,
            initialData: { refreshed: false },
            staleTime: Infinity,
            queryFn: () => {
              started.push(index)
              return refreshes[index].promise
            },
          })
      )
      const unsubscribes = observers.map((observer) =>
        observer.subscribe(() => {})
      )
      let closed = false
      const mutation = new MutationObserver(client, {
        mutationFn: () => reply.promise,
        onSuccess: () => invalidateSubscriptionQueries(client),
      })
      const unsubscribeMutation = mutation.subscribe(() => {})
      try {
        const importPromise = mutation.mutate(undefined, {
          onSuccess: () => {
            closed = true
          },
        })
        expect(closed).toBe(false)
        expect(mutation.getCurrentResult().status).toBe("pending")
        expect(started).toEqual([])

        reply.resolve({ imported: 2 })
        await importPromise
        expect(closed).toBe(true)
        expect(mutation.getCurrentResult().status).toBe("success")
        expect(started).toEqual([0, 1, 2, 3, 4, 5, 6])
        for (const queryKey of SUBSCRIPTION_CHANGE_QUERY_KEYS) {
          expect(client.getQueryState(queryKey)?.fetchStatus).toBe("fetching")
          expect(client.getQueryData(queryKey)).toEqual({ refreshed: false })
        }

        for (const refresh of refreshes) {
          if (refreshOutcome === "success") refresh.resolve({ refreshed: true })
          else refresh.reject(new Error("status unavailable during restart"))
        }
        await Promise.allSettled(refreshes.map((refresh) => refresh.promise))
        await new Promise((resolve) => setTimeout(resolve, 0))
        expect(mutation.getCurrentResult().status).toBe("success")
        expect(closed).toBe(true)
        for (const queryKey of SUBSCRIPTION_CHANGE_QUERY_KEYS) {
          expect(client.getQueryState(queryKey)?.status).toBe(refreshOutcome)
        }
      } finally {
        for (const refresh of refreshes) refresh.resolve({ refreshed: true })
        unsubscribeMutation()
        for (const unsubscribe of unsubscribes) unsubscribe()
        client.clear()
      }
    }
  )

  test("a failed import leaves the dialog open and does not invalidate inventory", async () => {
    const client = new QueryClient()
    for (const queryKey of SUBSCRIPTION_CHANGE_QUERY_KEYS)
      client.setQueryData(queryKey, { existing: true })
    let closed = false
    const error = new Error("import rejected")
    const mutation = new MutationObserver(client, {
      mutationFn: async () => {
        throw error
      },
      onSuccess: () => invalidateSubscriptionQueries(client),
      retry: false,
    })
    const unsubscribe = mutation.subscribe(() => {})
    try {
      await expect(
        mutation.mutate(undefined, {
          onSuccess: () => {
            closed = true
          },
        })
      ).rejects.toBe(error)
      expect(closed).toBe(false)
      expect(mutation.getCurrentResult().status).toBe("error")
      for (const queryKey of SUBSCRIPTION_CHANGE_QUERY_KEYS)
        expect(client.getQueryState(queryKey)?.isInvalidated).toBe(false)
    } finally {
      unsubscribe()
      client.clear()
    }
  })

  test("the production import hook uses the same background invalidation and preserves callbacks", () => {
    const source = readFileSync(
      new URL("../src/api/mutations.ts", import.meta.url),
      "utf8"
    )
    const hook = source
      .split("export const usePostSubscriptionApplyMutation")[1]
      .split("export const usePostTransportActionMutation")[0]
    expect(hook).toContain("invalidateSubscriptionQueries(queryClient)")
    expect(hook).not.toContain("await invalidateSubscriptionQueries")
    expect(hook).not.toContain("queryClient.invalidateQueries")
    expect(hook).toContain("await options?.mutation?.onSuccess?.(")
  })
})

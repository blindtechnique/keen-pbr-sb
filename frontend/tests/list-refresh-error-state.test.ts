import { describe, expect, spyOn, test } from "bun:test"
import { MutationObserver, QueryClient } from "@tanstack/react-query"

import { getPostListsRefreshMutationOptions } from "../src/api/generated/keen-api"
import { withListRefreshInvalidation } from "../src/api/mutations"
import { invalidationKeysAfterListRefreshMutation } from "../src/api/query-keys"

describe("failed list refresh state", () => {
  test("invalidates routing and cached list state before delivering a failed apply", async () => {
    const client = new QueryClient({
      defaultOptions: {
        queries: { retry: false },
        mutations: { retry: false },
      },
    })
    for (const key of invalidationKeysAfterListRefreshMutation) {
      client.setQueryData(key, { previous: true })
    }
    const payload = {
      code: "list_refresh_apply_failed",
      error: "List routing application failed",
      params: { stage: "terminal", runtime_result: "unknown" },
      refreshed_lists: ["work"],
      changed_lists: ["work"],
      failed_lists: [],
      reloaded: false,
    }
    const request = spyOn(globalThis, "fetch").mockResolvedValueOnce(
      new Response(JSON.stringify(payload), {
        status: 503,
        headers: { "Content-Type": "application/json" },
      })
    )
    let successCalls = 0
    let errorCalls = 0
    const observer = new MutationObserver(
      client,
      getPostListsRefreshMutationOptions(
        withListRefreshInvalidation(client, {
          mutation: {
            onSuccess: () => {
              successCalls += 1
            },
            onError: () => {
              errorCalls += 1
              for (const key of invalidationKeysAfterListRefreshMutation) {
                expect(client.getQueryState(key)?.isInvalidated).toBe(true)
              }
            },
          },
        })
      )
    )
    try {
      await expect(
        observer.mutate({ data: { name: "work" } })
      ).rejects.toMatchObject({
        status: 503,
        details: payload,
      })
      expect(request).toHaveBeenCalledTimes(1)
      expect(successCalls).toBe(0)
      expect(errorCalls).toBe(1)
    } finally {
      request.mockRestore()
      client.clear()
    }
  })
})

import { describe, expect, spyOn, test } from "bun:test"
import { readFileSync } from "node:fs"
import { MutationObserver, QueryClient } from "@tanstack/react-query"

import { getPostConfigSaveMutationOptions } from "../src/api/generated/keen-api"
import { isConfigMutationPending } from "../src/api/mutations"

const editor = readFileSync(
  new URL("../src/pages/transport-upsert-page.tsx", import.meta.url),
  "utf8"
)
const upsert = readFileSync(
  new URL("../src/components/shared/upsert-page.tsx", import.meta.url),
  "utf8"
)

describe("linked transport edit apply blocks the existing close control", () => {
  test("the editor uses the tracked apply hook, not an untracked raw request", () => {
    expect(editor).toContain(
      "const routeApplyMutation = useApplyConfigMutation()"
    )
    expect(editor).toContain("await routeApplyMutation.mutateAsync()")
    expect(editor).toContain("routeApplyMutation.isPending")
    expect(editor).not.toContain("await postConfigSave()")
    expect(upsert).toContain(
      "const mutationPending = useConfigMutationPending()"
    )
    expect(upsert).toMatch(
      /const close = useCallback\(\(\) => \{\s*if \(mutationPending\) \{\s*return/
    )
  })

  for (const status of [200, 503]) {
    test(`apply stays counted until its delayed HTTP ${status} response settles`, async () => {
      const client = new QueryClient({
        defaultOptions: { mutations: { retry: false } },
      })
      let respond!: (response: Response) => void
      const fetchSpy = spyOn(globalThis, "fetch").mockImplementation(
        () =>
          new Promise<Response>((resolve) => {
            respond = resolve
          })
      )
      const observer = new MutationObserver(
        client,
        getPostConfigSaveMutationOptions()
      )
      const closeIsBlocked = () =>
        isConfigMutationPending(
          0,
          client.isMutating({ mutationKey: ["postConfigSave"] })
        )
      try {
        expect(closeIsBlocked()).toBe(false)
        const result = observer.mutate().then(
          () => "saved",
          () => "failed"
        )
        // The routing-draft mutation is already finished. Only this apply
        // may keep the editor's shared close control disabled now.
        await Promise.resolve()
        expect(fetchSpy).toHaveBeenCalledTimes(1)
        expect(closeIsBlocked()).toBe(true)
        expect(observer.getCurrentResult().isPending).toBe(true)
        respond(
          Response.json(
            status === 200
              ? { status: "saved" }
              : { error: "apply unavailable" },
            { status }
          )
        )
        expect(await result).toBe(status === 200 ? "saved" : "failed")
        expect(closeIsBlocked()).toBe(false)
        expect(observer.getCurrentResult().isPending).toBe(false)
      } finally {
        fetchSpy.mockRestore()
        client.clear()
      }
    })
  }
})

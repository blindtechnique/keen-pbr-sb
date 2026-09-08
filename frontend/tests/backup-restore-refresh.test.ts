import { afterEach, describe, expect, test } from "bun:test"
import { QueryClient } from "@tanstack/react-query"

import {
  BACKUP_RESTORE_QUERY_KEYS,
  refreshAfterBackupRestore,
} from "../src/api/backup-refresh"
import { queryKeys } from "../src/api/query-keys"
import { rebaseSettingsDraft } from "../src/pages/general-config-form-state"

const originalFetch = globalThis.fetch
afterEach(() => {
  globalThis.fetch = originalFetch
})
const configResponse = (route: string) => ({
  config: { route: { rules: [{ outbound: route }] } },
  is_draft: false,
})
const response = (data: unknown) => Response.json(data)

describe("backup REST completion without SSE", () => {
  test("replaces the config baseline and invalidates related cached data", async () => {
    const client = new QueryClient()
    for (const key of BACKUP_RESTORE_QUERY_KEYS)
      client.setQueryData(key, { old: true })
    const requests: string[] = []
    globalThis.fetch = (async (url) => {
      requests.push(String(url))
      return response(configResponse("restored-vpn"))
    }) as typeof fetch
    try {
      await refreshAfterBackupRestore(client)
      expect(client.getQueryData(queryKeys.config())).toMatchObject({
        status: 200,
        data: configResponse("restored-vpn"),
      })
      expect(requests).toEqual(["/api/config"])
      for (const key of BACKUP_RESTORE_QUERY_KEYS.slice(1)) {
        expect(client.getQueryState(key)?.isInvalidated).toBe(true)
      }
    } finally {
      client.clear()
    }
  })

  test("a late pre-restore GET cannot overwrite the restored document", async () => {
    const client = new QueryClient()
    let finishOld!: (value: unknown) => void
    const old = client
      .fetchQuery({
        queryKey: queryKeys.config(),
        queryFn: () =>
          new Promise((resolve) => {
            finishOld = resolve
          }),
      })
      .catch(() => undefined)
    globalThis.fetch = (async () =>
      response(configResponse("new"))) as typeof fetch
    try {
      await refreshAfterBackupRestore(client)
      finishOld({ status: 200, data: configResponse("old") })
      await old
      expect(client.getQueryData(queryKeys.config())).toMatchObject({
        data: configResponse("new"),
      })
    } finally {
      client.clear()
    }
  })

  test("failed refresh marks config unavailable, without retrying a restoration", async () => {
    const client = new QueryClient()
    client.setQueryData(queryKeys.config(), {
      status: 200,
      data: configResponse("old"),
    })
    const requests: string[] = []
    globalThis.fetch = (async (url) => {
      requests.push(String(url))
      return new Response("offline", { status: 503 })
    }) as typeof fetch
    try {
      await expect(refreshAfterBackupRestore(client)).rejects.toMatchObject({
        status: 503,
      })
      expect(client.getQueryState(queryKeys.config())?.status).toBe("error")
      expect(requests).toEqual(["/api/config"])
    } finally {
      client.clear()
    }
  })

  test("a dirty checkbox does not replay untouched old DNS fields after restore", () => {
    const before = {
      ttl: true,
      clientDnsEnforcement: false,
      firefoxDohCanary: true,
      interfaces: ["br0"],
    }
    const edited = { ...before, ttl: false }
    const restored = {
      ttl: true,
      clientDnsEnforcement: true,
      firefoxDohCanary: false,
      interfaces: ["br1"],
    }
    expect(rebaseSettingsDraft(before, edited, restored)).toEqual({
      ...restored,
      ttl: false,
    })
    expect(rebaseSettingsDraft(before, before, restored)).toEqual(restored)
  })

  test("restore and rollback share the refresh; the settings form rebases its values", async () => {
    const dialog = await Bun.file(
      new URL("../src/components/settings/backup-dialogs.tsx", import.meta.url)
    ).text()
    expect(dialog).toContain("await refreshAfterBackupRestore(queryClient)")
    expect(dialog.indexOf("await refreshAfterBackupRestore")).toBeGreaterThan(
      dialog.indexOf("await rollbackBackup()")
    )
    const page = await Bun.file(
      new URL("../src/pages/general-config-page.tsx", import.meta.url)
    ).text()
    expect(page).toContain("rebaseSettingsDraft(")
    expect(page).toContain("form.reset(nextBaseline)")
    expect(page).toContain("form.setFieldValue(key, rebased[key])")
    expect(page).toContain("configQuery.isError || !loadedConfig")
  })
})

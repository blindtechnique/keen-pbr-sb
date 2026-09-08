import { describe, expect, spyOn, test } from "bun:test"

import {
  createBackup,
  createDefaultBackupSelection,
  parseBackupBundle,
  readBackupFile,
  restoreBackup,
  toBackupWireSelection,
} from "../src/lib/backup"
import { filterNfqwsBackupBundle } from "../src/lib/nfqws-backup"

describe("shared backup groups", () => {
  test("normalizes the old combined nfqws group", () => {
    const parsed = parseBackupBundle({
      format: "keen-pbr-sb-backup",
      schema: 1,
      created_at: 1,
      groups: {
        general: true,
        transports: true,
        outbounds: true,
        dns: true,
        routing: true,
        nfqws: true,
      },
      data: {},
    })

    expect(parsed.groups.nfqws_config).toBe(true)
    expect(parsed.groups.nfqws_lists).toBe(true)
  })

  test("keeps the deprecated wire flag for older daemons", () => {
    const selection = createDefaultBackupSelection()
    selection.nfqws_lists = false

    expect(toBackupWireSelection(selection)).toMatchObject({
      nfqws: true,
      nfqws_config: true,
      nfqws_lists: false,
    })
  })

  test("reads the new split nfqws groups without the deprecated flag", () => {
    const parsed = parseBackupBundle({
      format: "keen-pbr-sb-backup",
      schema: 1,
      created_at: 1,
      groups: {
        general: false,
        transports: false,
        outbounds: false,
        dns: false,
        routing: false,
        nfqws_config: true,
        nfqws_lists: false,
      },
      data: {},
    })

    expect(parsed.groups).toMatchObject({
      nfqws: true,
      nfqws_config: true,
      nfqws_lists: false,
    })
  })

  test("does not inherit a missing split group from the legacy alias", () => {
    const parsed = parseBackupBundle({
      format: "keen-pbr-sb-backup",
      schema: 1,
      created_at: 1,
      groups: {
        general: false,
        transports: false,
        outbounds: false,
        dns: false,
        routing: false,
        nfqws_config: false,
        nfqws: true,
      },
      data: {},
    })

    expect(parsed.groups).toMatchObject({
      nfqws_config: false,
      nfqws_lists: false,
      nfqws: true,
    })
  })

  test("filters a combined response returned by an older daemon", async () => {
    const fetchSpy = spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          format: "keen-pbr-sb-backup",
          schema: 1,
          created_at: 1,
          groups: {
            general: false,
            transports: false,
            outbounds: false,
            dns: false,
            routing: false,
            nfqws: true,
          },
          data: {
            nfqws: {
              "nfqws2/nfqws2.conf": "config",
              "nfqws2/lists/user.list": "list",
            },
          },
        }),
        {
          headers: { "Content-Type": "application/json" },
          status: 200,
        }
      )
    )

    try {
      const selection = createDefaultBackupSelection()
      Object.assign(selection, {
        general: false,
        transports: false,
        outbounds: false,
        dns: false,
        routing: false,
        nfqws_config: false,
        nfqws_lists: true,
      })

      const backup = await createBackup(selection)

      expect(backup.data.nfqws).toEqual({
        "nfqws2/lists/user.list": "list",
      })
    } finally {
      fetchSpy.mockRestore()
    }
  })

  test("rejects backups without legacy or split nfqws declarations", () => {
    expect(() =>
      parseBackupBundle({
        format: "keen-pbr-sb-backup",
        schema: 1,
        created_at: 1,
        groups: {
          general: false,
          transports: false,
          outbounds: false,
          dns: false,
          routing: false,
        },
        data: {},
      })
    ).toThrow()
  })
})

describe("backup source configuration version", () => {
  function dnsOnlyBundle() {
    return {
      format: "keen-pbr-sb-backup",
      schema: 1,
      created_at: 1,
      groups: {
        general: false,
        transports: false,
        outbounds: false,
        dns: true,
        routing: false,
        nfqws: false,
      },
      data: { dns: { fallback: ["default_dns"] } },
    }
  }

  for (const version of [2, 3]) {
    test(`preserves source ${version} through create, file parse, filtering and restore`, async () => {
      const source = { ...dnsOnlyBundle(), config_schema_version: version }
      const fetchSpy = spyOn(globalThis, "fetch")
        .mockResolvedValueOnce(
          new Response(JSON.stringify(source), {
            headers: { "Content-Type": "application/json" },
            status: 200,
          })
        )
        .mockResolvedValueOnce(new Response("{}", { status: 200 }))

      try {
        const selection = createDefaultBackupSelection()
        Object.assign(selection, source.groups, {
          nfqws_config: false,
          nfqws_lists: false,
        })
        const created = await createBackup(selection)
        expect(created.config_schema_version).toBe(version)
        expect(created.data).toEqual(source.data)
        expect(created.data).not.toHaveProperty("general")

        const loaded = await readBackupFile(
          new File([JSON.stringify(created)], "synthetic-dns-backup.json")
        )
        const filtered = filterNfqwsBackupBundle(loaded, false, false)
        expect(filtered.config_schema_version).toBe(version)
        await restoreBackup(filtered)

        expect(fetchSpy.mock.calls[1]?.[0]).toBe("/api/backup/restore")
        const restored = JSON.parse(
          fetchSpy.mock.calls[1]?.[1]?.body as string
        )
        expect(restored.config_schema_version).toBe(version)
        expect(restored.schema).toBe(1)
        expect(restored.data).toEqual(source.data)
      } finally {
        fetchSpy.mockRestore()
      }
    })
  }

  test("keeps absent source metadata absent in a legacy archive", async () => {
    const parsed = parseBackupBundle(dnsOnlyBundle())
    const filtered = filterNfqwsBackupBundle(parsed, false, false)
    expect(parsed).not.toHaveProperty("config_schema_version")
    expect(filtered).not.toHaveProperty("config_schema_version")
    const fetchSpy = spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("{}", { status: 200 })
    )
    try {
      await restoreBackup(filtered)
      const restored = JSON.parse(fetchSpy.mock.calls[0]?.[1]?.body as string)
      expect(restored).not.toHaveProperty("config_schema_version")
    } finally {
      fetchSpy.mockRestore()
    }
  })

  test("does not silently drop malformed source metadata", () => {
    for (const value of [
      undefined, null, "2", 0, -1, 1.5, Number.NaN,
      Number.POSITIVE_INFINITY, Number.MAX_SAFE_INTEGER + 1, {}, [],
    ]) {
      expect(() => parseBackupBundle({
        ...dnsOnlyBundle(), config_schema_version: value,
      })).toThrow()
    }
  })
})

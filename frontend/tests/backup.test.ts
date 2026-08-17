import { describe, expect, spyOn, test } from "bun:test"

import {
  createBackup,
  createDefaultBackupSelection,
  parseBackupBundle,
  toBackupWireSelection,
} from "../src/lib/backup"

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

import { describe, expect, test } from "bun:test"

import {
  InvalidNfqwsBackupError,
  createNfqwsBackupSelection,
  filterNfqwsBackupBundle,
  parseNfqwsBackupBundle,
  selectNfqwsBackupBundle,
  selectNfqwsBackupFiles,
} from "../src/lib/nfqws-backup"
import { parseBackupBundle } from "../src/lib/backup"

const combinedBundle = {
  format: "keen-pbr-sb-nfqws",
  version: 1,
  files: {
    config: {
      "nfqws2.conf": "NFQWS_ARGS=example\n",
    },
    list: {
      "user.list": "example.com\n",
    },
  },
} as const

describe("nfqws2 backup helpers", () => {
  test("reads the existing combined v1 bundle", () => {
    expect(parseNfqwsBackupBundle(combinedBundle)).toEqual(combinedBundle)
  })

  test("selects only the requested category from a combined backup", () => {
    const parsed = parseNfqwsBackupBundle(combinedBundle)

    expect(selectNfqwsBackupFiles(parsed.files, "config")).toEqual({
      config: combinedBundle.files.config,
    })
    expect(selectNfqwsBackupFiles(parsed.files, "list")).toEqual({
      list: combinedBundle.files.list,
    })
  })

  test("rejects malformed and empty bundles", () => {
    expect(() =>
      parseNfqwsBackupBundle({
        ...combinedBundle,
        files: { list: { "user.list": 42 } },
      })
    ).toThrow(InvalidNfqwsBackupError)

    expect(() =>
      parseNfqwsBackupBundle({
        ...combinedBundle,
        files: {},
      })
    ).toThrow(InvalidNfqwsBackupError)
  })

  test("maps scopes to the shared backup groups", () => {
    expect(createNfqwsBackupSelection("config")).toMatchObject({
      nfqws_config: true,
      nfqws_lists: false,
    })
    expect(createNfqwsBackupSelection("list")).toMatchObject({
      nfqws_config: false,
      nfqws_lists: true,
    })
    expect(createNfqwsBackupSelection("all")).toMatchObject({
      nfqws_config: true,
      nfqws_lists: true,
    })
  })

  test("filters a shared backup to the selected nfqws2 scope", () => {
    const bundle = parseBackupBundle({
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
          "nfqws2/nfqws2.conf": { encoding: "base64", data: "Y29uZmln" },
          "nfqws2/lua/custom.lua.gz": { encoding: "base64", data: "bHVh" },
          "nfqws2/lists/user.list": { encoding: "base64", data: "bGlzdA==" },
          "strategies/custom.conf": {
            encoding: "base64",
            data: "c3RyYXRlZ3k=",
          },
        },
      },
    })

    expect(
      Object.keys(selectNfqwsBackupBundle(bundle, "config").data.nfqws ?? {})
    ).toEqual([
      "nfqws2/nfqws2.conf",
      "nfqws2/lua/custom.lua.gz",
      "strategies/custom.conf",
    ])
    expect(
      Object.keys(selectNfqwsBackupBundle(bundle, "list").data.nfqws ?? {})
    ).toEqual(["nfqws2/lists/user.list"])
  })

  test("filters a legacy daemon response to the requested split group", () => {
    const bundle = parseBackupBundle({
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
          "nfqws2/nfqws2.conf": { encoding: "base64", data: "Y29uZmln" },
          "nfqws2/lists/user.list": { encoding: "base64", data: "bGlzdA==" },
        },
      },
    })

    const filtered = filterNfqwsBackupBundle(bundle, false, true)

    expect(filtered.groups).toMatchObject({
      nfqws_config: false,
      nfqws_lists: true,
      nfqws: true,
    })
    expect(Object.keys(filtered.data.nfqws ?? {})).toEqual([
      "nfqws2/lists/user.list",
    ])
  })

  test("keeps unrelated backup data and removes unrequested nfqws data", () => {
    const bundle = parseBackupBundle({
      format: "keen-pbr-sb-backup",
      schema: 1,
      created_at: 1,
      groups: {
        general: true,
        transports: false,
        outbounds: false,
        dns: false,
        routing: false,
        nfqws: true,
      },
      data: {
        general: { locale: "ru" },
        nfqws: {
          "nfqws2/nfqws2.conf": "config",
        },
      },
    })

    const filtered = filterNfqwsBackupBundle(bundle, false, false)

    expect(filtered.data).toEqual({
      general: { locale: "ru" },
    })
    expect(filtered.groups).toMatchObject({
      general: true,
      nfqws_config: false,
      nfqws_lists: false,
      nfqws: false,
    })
  })

  test("scoped restore clears unrelated group declarations", () => {
    const bundle = parseBackupBundle({
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
      data: {
        general: { locale: "ru" },
        nfqws: {
          "nfqws2/lists/user.list": "list",
        },
      },
    })

    expect(selectNfqwsBackupBundle(bundle, "list").groups).toMatchObject({
      general: false,
      transports: false,
      outbounds: false,
      dns: false,
      routing: false,
      nfqws_config: false,
      nfqws_lists: true,
      nfqws: true,
    })
  })

  test("rejects unsafe shared paths and legacy names", () => {
    const unsafe = parseBackupBundle({
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
          "nfqws2/../outside.conf": "unsafe",
        },
      },
    })

    expect(() => selectNfqwsBackupBundle(unsafe, "config")).toThrow(
      InvalidNfqwsBackupError
    )
    expect(() =>
      parseNfqwsBackupBundle({
        ...combinedBundle,
        files: {
          config: {
            "../nfqws2.conf": "unsafe",
          },
        },
      })
    ).toThrow(InvalidNfqwsBackupError)
  })
})

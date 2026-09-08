import { describe, expect, spyOn, test } from "bun:test"

import {
  saveNfqwsConnectivityExclusions,
  nfqwsConnectivityListWasSaved,
} from "../src/api/nfqws"
import {
  ANDROID_CONNECTIVITY_DOMAINS,
  androidConnectivityEnabled,
  setAndroidConnectivityExclusions,
} from "../src/lib/nfqws-connectivity"
import {
  formatNfqwsConfig,
  nfqwsConfigChanged,
  parseNfqwsConfig,
} from "../src/lib/nfqws-config"

describe("nfqws settings dirty state", () => {
  test("saving one setting does not reformat the strategy or add untouched defaults", () => {
    const source =
      '# Keep my strategy\nNFQWS_ARGS="--filter-tcp=443\n  --lua-desync=fake"\nLOG_LEVEL=0\n'
    const form = parseNfqwsConfig(source)
    expect(formatNfqwsConfig(source, form)).toBe(source)
    expect(formatNfqwsConfig(source, { ...form, LOG_LEVEL: true })).toBe(
      source.replace("LOG_LEVEL=0", "LOG_LEVEL=1")
    )
  })
  test("load and reverting fields do not enable Save", () => {
    const baseline = parseNfqwsConfig('TCP_PORTS="80,443"\nIPV6_ENABLED=1\n')
    expect(nfqwsConfigChanged(null, baseline)).toBe(false)
    expect(nfqwsConfigChanged({ ...baseline }, baseline)).toBe(false)
    const form = { ...baseline, TCP_PORTS: "443", IPV6_ENABLED: false }
    expect(nfqwsConfigChanged(form, baseline)).toBe(true)
    form.TCP_PORTS = baseline.TCP_PORTS
    expect(nfqwsConfigChanged(form, baseline)).toBe(true)
    form.IPV6_ENABLED = baseline.IPV6_ENABLED
    expect(nfqwsConfigChanged(form, baseline)).toBe(false)
  })
})

describe("Android connectivity exclusions", () => {
  test("adds the twelve requested domains once and removes only its block", () => {
    const original = "# My exclusions\nmy.example\ngoogle.com\n"
    const enabled = setAndroidConnectivityExclusions(original, true)
    expect(ANDROID_CONNECTIVITY_DOMAINS).toHaveLength(12)
    expect(androidConnectivityEnabled(original)).toBe(false)
    expect(androidConnectivityEnabled(enabled)).toBe(true)
    for (const domain of ANDROID_CONNECTIVITY_DOMAINS) {
      expect(
        enabled.split("\n").filter((line) => line === domain)
      ).toHaveLength(1)
    }
    expect(setAndroidConnectivityExclusions(enabled, true)).toBe(enabled)
    expect(setAndroidConnectivityExclusions(enabled, false)).toBe(original)
    expect(setAndroidConnectivityExclusions(original, false)).toBe(original)
  })

  test("keeps pre-existing case, comments and CRLF, even if all domains already exist", () => {
    const original =
      ANDROID_CONNECTIVITY_DOMAINS.map(
        (domain) => `  ${domain.toUpperCase()} # manual`
      ).join("\r\n") + "\r\n"
    const enabled = setAndroidConnectivityExclusions(original, true)
    expect(androidConnectivityEnabled(enabled)).toBe(true)
    expect(enabled.startsWith(original)).toBe(true)
    expect(setAndroidConnectivityExclusions(enabled, false)).toBe(original)
    expect(enabled.split("\n")).toHaveLength(15)
  })

  test("keeps unrelated edits inside its block and a user's separate duplicate", () => {
    const enabled = setAndroidConnectivityExclusions("", true)
    const edited =
      enabled.replace(
        "connectivitycheck.gstatic.com\n",
        "connectivitycheck.gstatic.com\n# user note\nuser.example\n"
      ) + "google.com\n"
    expect(setAndroidConnectivityExclusions(edited, false)).toBe(
      "# user note\nuser.example\ngoogle.com\n"
    )
  })

  test("repairs an incomplete domain set but does not delete an unclosed block", () => {
    const enabled = setAndroidConnectivityExclusions("", true)
    const partial = enabled.replace("clients3.google.com\n", "")
    expect(androidConnectivityEnabled(partial)).toBe(false)
    expect(
      androidConnectivityEnabled(
        setAndroidConnectivityExclusions(partial, true)
      )
    ).toBe(true)
    const unclosed = "# keen-pbr: android-connectivity begin\nuser.example\n"
    expect(setAndroidConnectivityExclusions(unclosed, false)).toBe(unclosed)
  })

  test("appends safely to files without a final newline and does not treat strict domains as subtree coverage", () => {
    const source =
      "^google.com\nconnectivitycheck.android.com#not-a-comment\nmanual.example"
    const enabled = setAndroidConnectivityExclusions(source, true)
    expect(enabled.startsWith(source + "\n")).toBe(true)
    expect(enabled.split("\n")).toContain("google.com")
    expect(enabled.split("\n")).toContain("connectivitycheck.android.com")
  })
})

describe("connectivity checkbox uses existing nfqws file API", () => {
  test("an unsuccessful restart still reports the saved list for the form baseline", async () => {
    const fetchSpy = spyOn(globalThis, "fetch").mockImplementation(
      async (_url, init) =>
        Response.json(
          init?.method === "POST"
            ? { ok: false, saved: 1, output: "restart failed", status: 1 }
            : { files: [] }
        )
    )
    try {
      const error = await saveNfqwsConnectivityExclusions({
        enabled: true,
        restart: true,
        existingFile: false,
      }).catch((reason: unknown) => reason)
      expect(nfqwsConnectivityListWasSaved(error)).toBe(true)
      expect(nfqwsConnectivityListWasSaved(new Error("write failed"))).toBe(
        false
      )
      expect(nfqwsConnectivityListWasSaved(null)).toBe(false)
    } finally {
      fetchSpy.mockRestore()
    }
  })
  test("merges a fresh file and applies once without touching configuration or other lists", async () => {
    const calls: Record<string, unknown>[] = []
    const fetchSpy = spyOn(globalThis, "fetch").mockImplementation(
      async (_url, init) => {
        const request = JSON.parse(String(init?.body)) as Record<
          string,
          unknown
        >
        calls.push(request)
        return Response.json(
          request.action === "read_file"
            ? { content: "new-manual.example\ngoogle.com\n" }
            : { ok: true }
        )
      }
    )
    try {
      await saveNfqwsConnectivityExclusions({
        enabled: true,
        restart: true,
        existingFile: true,
      })
      expect(calls).toHaveLength(2)
      expect(calls[0]).toEqual({
        action: "read_file",
        category: "list",
        name: "exclude.list",
      })
      expect(calls[1]).toEqual({
        action: "save_files",
        restart: true,
        files: [
          {
            category: "list",
            name: "exclude.list",
            content: setAndroidConnectivityExclusions(
              "new-manual.example\ngoogle.com\n",
              true
            ),
          },
        ],
      })
    } finally {
      fetchSpy.mockRestore()
    }
  })

  test("creates a missing list without starting a stopped nfqws", async () => {
    const fetchSpy = spyOn(globalThis, "fetch").mockImplementation(
      async (_url, init) =>
        Response.json(init?.method === "POST" ? { ok: true } : { files: [] })
    )
    try {
      await saveNfqwsConnectivityExclusions({
        enabled: true,
        restart: false,
        existingFile: false,
      })
      expect(fetchSpy).toHaveBeenCalledTimes(2)
      const body = JSON.parse(String(fetchSpy.mock.calls[1][1]?.body))
      expect(body.restart).toBe(false)
      expect(androidConnectivityEnabled(body.files[0].content)).toBe(true)
    } finally {
      fetchSpy.mockRestore()
    }
  })

  test("a failed read never overwrites the file and a failed apply is surfaced", async () => {
    const fetchSpy = spyOn(globalThis, "fetch").mockResolvedValue(
      Response.json({ ok: false, error: "read failed" }, { status: 500 })
    )
    try {
      await expect(
        saveNfqwsConnectivityExclusions({
          enabled: true,
          restart: true,
          existingFile: true,
        })
      ).rejects.toThrow("read failed")
      expect(fetchSpy).toHaveBeenCalledTimes(1)
      fetchSpy.mockImplementation(async (_url, init) =>
        Response.json(
          init?.method === "POST"
            ? { ok: false, output: "restart failed" }
            : { files: [] }
        )
      )
      await expect(
        saveNfqwsConnectivityExclusions({
          enabled: true,
          restart: true,
          existingFile: false,
        })
      ).rejects.toThrow("restart failed")
    } finally {
      fetchSpy.mockRestore()
    }
  })

  test("preserves a manual list created since the page opened", async () => {
    const requests: Record<string, unknown>[] = []
    const fetchSpy = spyOn(globalThis, "fetch").mockImplementation(
      async (_url, init) => {
        if (!init?.body)
          return Response.json({
            files: [{ category: "list", name: "exclude.list" }],
          })
        const request = JSON.parse(String(init.body)) as Record<string, unknown>
        requests.push(request)
        return Response.json(
          request.action === "read_file"
            ? { content: "added-elsewhere.example\n" }
            : { ok: true }
        )
      }
    )
    try {
      await saveNfqwsConnectivityExclusions({
        enabled: true,
        restart: false,
        existingFile: false,
      })
      expect(fetchSpy).toHaveBeenCalledTimes(3)
      expect(requests[1]).toEqual({
        action: "save_files",
        restart: false,
        files: [
          {
            category: "list",
            name: "exclude.list",
            content: setAndroidConnectivityExclusions(
              "added-elsewhere.example\n",
              true
            ),
          },
        ],
      })
    } finally {
      fetchSpy.mockRestore()
    }
  })
})

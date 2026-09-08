import { describe, expect, test } from "bun:test"
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import {
  collectConfigKnownFields,
  renderConfigKnownFields,
  updateGeneratedFile,
} from "./generate_config_known_fields.cjs"

const ref = (name: string) => ({ $ref: `#/components/schemas/${name}` })

describe("configuration known-field generation", () => {
  test("follows arrays maps and inline objects but excludes unrelated API schemas", () => {
    const fields = collectConfigKnownFields({
      ConfigObject: { type: "object", properties: {
        list: { type: "array", items: ref("Child") },
        map: { type: "object", additionalProperties: ref("Mapped") },
        inline: { type: "object", properties: { child: ref("Child") } },
      }, example: { $ref: "#/components/schemas/AuthCredentials" } },
      Child: { type: "object", properties: { "wire-name": { type: "string" } } },
      Mapped: { type: "object", properties: { enabled: { type: "boolean" } } },
      AuthCredentials: { type: "object", properties: { password: { type: "string" } } },
    })
    expect(fields).toEqual({
      Child: ["wire-name"], ConfigObject: ["inline", "list", "map"], Mapped: ["enabled"],
    })
  })

  test("retains original schema names and handles referenced enums without object metadata", () => {
    expect(collectConfigKnownFields({
      ConfigObject: { properties: { rule: ref("DnsRule"), mode: ref("Mode") } },
      DnsRule: { type: "object", properties: { list: {}, server: {} } },
      Mode: { type: "string", enum: ["default"] },
    })).toEqual({ ConfigObject: ["mode", "rule"], DnsRule: ["list", "server"] })
  })

  test("collects composition and alias keys without adopting nested child keys", () => {
    const fields = collectConfigKnownFields({
      ConfigObject: { type: "object", properties: { object: ref("Alias") } },
      Alias: ref("Composed"),
      Composed: { allOf: [ref("Base"), { properties: { own: { type: "string" } } }] },
      Base: { properties: { nested: ref("Child") } },
      Child: { properties: { child_key: {} } },
    })
    expect(fields.Alias).toEqual(["nested", "own"])
    expect(fields.Composed).toEqual(["nested", "own"])
    expect(fields.Child).toEqual(["child_key"])
  })

  test("handles recursive references once", () => {
    expect(collectConfigKnownFields({
      ConfigObject: { properties: { nodes: { type: "array", items: ref("Node") } } },
      Node: { properties: { next: ref("Node"), root: ref("ConfigObject") } },
    })).toEqual({ ConfigObject: ["nodes"], Node: ["next", "root"] })
  })

  test("sorts output deterministically without mutating the schema", () => {
    const left = { ConfigObject: { properties: { z: ref("Child"), a: {} } },
      Child: { properties: { b: {}, a: {} } } }
    const right = { Child: { properties: { a: {}, b: {} } },
      ConfigObject: { properties: { a: {}, z: ref("Child") } } }
    const before = JSON.stringify(left)
    expect(renderConfigKnownFields(left)).toBe(renderConfigKnownFields(right))
    expect(JSON.stringify(left)).toBe(before)
    expect(renderConfigKnownFields(left)).toContain("export const configKnownFields =")
  })

  test("reports missing roots broken references and unsupported external references", () => {
    expect(() => collectConfigKnownFields({})).toThrow("Missing ConfigObject")
    expect(() => collectConfigKnownFields({ ConfigObject: { properties: { field: ref("Missing") } } }))
      .toThrow("Missing configuration schema: Missing")
    expect(() => collectConfigKnownFields({ ConfigObject: { properties: {
      field: { $ref: "https://example.invalid/schema.json" },
    } } })).toThrow("Unsupported configuration schema reference")
  })

  test("check mode detects stale or missing output without creating or rewriting it", () => {
    const directory = mkdtempSync(join(tmpdir(), "kpbr-known-fields-"))
    const path = join(directory, "generated.ts")
    try {
      expect(updateGeneratedFile(path, "expected\n", true)).toBe(false)
      expect(() => readFileSync(path, "utf8")).toThrow()
      writeFileSync(path, "old\n")
      expect(updateGeneratedFile(path, "expected\n", true)).toBe(false)
      expect(readFileSync(path, "utf8")).toBe("old\n")
      expect(updateGeneratedFile(path, "expected\n", false)).toBe(true)
      expect(readFileSync(path, "utf8")).toBe("expected\n")
      writeFileSync(path, "expected\r\n")
      expect(updateGeneratedFile(path, "expected\n", true)).toBe(true)
      expect(readFileSync(path, "utf8")).toBe("expected\r\n")
    } finally {
      rmSync(directory, { recursive: true, force: true })
    }
  })
})

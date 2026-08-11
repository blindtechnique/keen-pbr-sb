import { readFileSync } from "node:fs"
import { join } from "node:path"

import { describe, expect, test } from "bun:test"

import { enTranslation } from "../i18n/en"
import { ruTranslation } from "../i18n/ru"
import {
  packageRollbackReasonKey,
  packageRollbackReasonKeys,
} from "./package-rollback"

// The wire names as the backend actually emits them, read from the function
// that emits them rather than from the enum declaration. The enum identifiers
// happen to match today, but it is `package_rollback_state_name` that decides
// what crosses the wire, and this gate has to break when that changes.
function backendStateNames(): Set<string> {
  const source = readFileSync(
    join(
      import.meta.dir,
      "..",
      "..",
      "..",
      "src",
      "update",
      "rollback_availability.cpp",
    ),
    "utf8",
  )
  const start = source.indexOf("const char* package_rollback_state_name(")
  expect(start).toBeGreaterThanOrEqual(0)
  const end = source.indexOf("\n}", start)
  expect(end).toBeGreaterThan(start)
  const body = source.slice(start, end)
  const names = new Set<string>()
  for (const match of body.matchAll(/return "([a-z_]+)";/g)) {
    names.add(match[1])
  }
  expect(names.size).toBeGreaterThan(1)
  return names
}

function leaf(dictionary: unknown, key: string): unknown {
  const update = (
    dictionary as {
      pages?: { settings?: { softwareUpdate?: Record<string, unknown> } }
    }
  ).pages?.settings?.softwareUpdate
  return update?.[key]
}

describe("packageRollbackReasonKey", () => {
  test("explains every state the backend can report as unavailable", () => {
    const backend = backendStateNames()
    // `available` is not a reason; every other state must have one, or an
    // operator meets a disabled button with nothing to act on.
    const expected = [...backend].filter((name) => name !== "available").sort()
    expect(Object.keys(packageRollbackReasonKeys).sort()).toEqual(expected)
  })

  test("never maps the available state to a reason", () => {
    expect(packageRollbackReasonKey("available")).toBeNull()
  })

  test("says nothing about a state it does not recognise", () => {
    // A page older than its backend must not invent an explanation.
    expect(packageRollbackReasonKey("state_added_later")).toBeNull()
    expect(packageRollbackReasonKey(undefined)).toBeNull()
    expect(packageRollbackReasonKey("")).toBeNull()
  })

  test("every reason resolves to real text in both languages", () => {
    for (const key of Object.values(packageRollbackReasonKeys)) {
      // i18next renders a missing key as the key itself, so a typo would show
      // the operator an identifier instead of a sentence.
      expect(typeof leaf(enTranslation, key)).toBe("string")
      expect(typeof leaf(ruTranslation, key)).toBe("string")
    }
    expect(typeof leaf(enTranslation, "rollbackUnavailable")).toBe("string")
    expect(typeof leaf(ruTranslation, "rollbackUnavailable")).toBe("string")
  })
})

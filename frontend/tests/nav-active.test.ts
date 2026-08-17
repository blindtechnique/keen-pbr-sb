import { describe, expect, test } from "bun:test"

import { matchesNavHref } from "../src/lib/nav-active"

describe("matchesNavHref", () => {
  test("root matches only exactly", () => {
    expect(matchesNavHref("/", "/")).toBe(true)
    expect(matchesNavHref("", "/")).toBe(true)
    expect(matchesNavHref("/lists", "/")).toBe(false)
    expect(matchesNavHref("/lists/create", "/")).toBe(false)
  })

  test("section matches self and children", () => {
    expect(matchesNavHref("/lists", "/lists")).toBe(true)
    expect(matchesNavHref("/lists/create", "/lists")).toBe(true)
    expect(matchesNavHref("/lists/foo/edit", "/lists")).toBe(true)
    expect(matchesNavHref("/routing-rules", "/lists")).toBe(false)
  })

  test("does not match sibling prefixes", () => {
    expect(matchesNavHref("/lists-backup", "/lists")).toBe(false)
  })

  test("aliases keep the merged section lit from the old editor paths", () => {
    const rules = ["/routing-rules", "/dns-rules"]

    expect(matchesNavHref("/rules", "/rules", rules)).toBe(true)
    expect(matchesNavHref("/routing-rules/5/edit", "/rules", rules)).toBe(true)
    expect(matchesNavHref("/dns-rules/create", "/rules", rules)).toBe(true)
    expect(matchesNavHref("/lists", "/rules", rules)).toBe(false)
  })

  test("alias list does not widen the match to siblings", () => {
    expect(
      matchesNavHref("/outbounds-backup", "/transports", ["/outbounds"])
    ).toBe(false)
    expect(
      matchesNavHref("/outbounds/tr_1/edit", "/transports", ["/outbounds"])
    ).toBe(true)
  })

  test("no aliases behaves exactly as before", () => {
    expect(matchesNavHref("/lists/create", "/lists")).toBe(true)
    expect(matchesNavHref("/routing-rules", "/lists")).toBe(false)
  })
})

import { describe, expect, test } from "bun:test"

import { resolveSortableTargetPosition } from "../src/hooks/use-pointer-sortable"

const slots = [
  { middle: 20, position: 0 },
  { middle: 60, position: 1 },
  { middle: 100, position: 2 },
  { middle: 140, position: 3 },
]

describe("pointer sortable target resolution", () => {
  test("moves down only after crossing each following row midpoint", () => {
    expect(resolveSortableTargetPosition(59, 0, slots, slots.length)).toBe(0)
    expect(resolveSortableTargetPosition(61, 0, slots, slots.length)).toBe(1)
    expect(resolveSortableTargetPosition(101, 0, slots, slots.length)).toBe(2)
    expect(resolveSortableTargetPosition(141, 0, slots, slots.length)).toBe(3)
  })

  test("moves up only after crossing each preceding row midpoint", () => {
    expect(resolveSortableTargetPosition(101, 3, slots, slots.length)).toBe(3)
    expect(resolveSortableTargetPosition(99, 3, slots, slots.length)).toBe(2)
    expect(resolveSortableTargetPosition(59, 3, slots, slots.length)).toBe(1)
    expect(resolveSortableTargetPosition(19, 3, slots, slots.length)).toBe(0)
  })

  test("ignores stale and invalid DOM positions", () => {
    expect(
      resolveSortableTargetPosition(
        61,
        0,
        [
          ...slots,
          { middle: Number.NaN, position: 1 },
          { middle: 80, position: 7 },
        ],
        slots.length
      )
    ).toBe(1)
  })

  test("keeps the current slot when its DOM candidate is unavailable", () => {
    expect(resolveSortableTargetPosition(61, 7, slots, slots.length)).toBe(-1)
  })
})

import { describe, expect, test } from "bun:test"

import type { Dependency, DependencyKind } from "../src/lib/dependencies"
import { planDependencyRows } from "../src/lib/dependencies"

function make(kind: DependencyKind, count: number): Dependency[] {
  return Array.from({ length: count }, (_, index) => ({
    kind,
    label: `${kind}-${index}`,
  }))
}

describe("planDependencyRows", () => {
  test("одна строка на вид связи, порядок первого появления", () => {
    const { rows, hiddenCount } = planDependencyRows(
      [...make("routingRule", 2), ...make("list", 1)],
      false
    )

    expect(rows.map((row) => row.kind)).toEqual(["routingRule", "list"])
    expect(rows[0]?.items).toHaveLength(2)
    expect(hiddenCount).toBe(0)
  })

  test("не больше трёх строк в свёрнутом виде", () => {
    const { rows, hiddenCount } = planDependencyRows(
      [
        ...make("routingRule", 1),
        ...make("list", 1),
        ...make("failoverGroup", 1),
        ...make("dnsRule", 1),
        ...make("dnsServer", 1),
      ],
      false
    )

    expect(rows).toHaveLength(3)
    expect(hiddenCount).toBe(2)
  })

  test("длинная строка тоже обрезается — иначе три строки занимают полэкрана", () => {
    const { rows, hiddenCount } = planDependencyRows(make("list", 11), false)

    expect(rows).toHaveLength(1)
    expect(rows[0]?.items).toHaveLength(3)
    expect(hiddenCount).toBe(8)
  })

  test("скрытыми считаются связи, а не виды", () => {
    const { hiddenCount } = planDependencyRows(
      [
        ...make("routingRule", 5),
        ...make("list", 5),
        ...make("failoverGroup", 5),
        ...make("dnsRule", 4),
      ],
      false
    )

    // Всего 19 связей, показаны три вида по три имени — прячется десять.
    expect(hiddenCount).toBe(10)
  })

  test("развёрнутый вид показывает всё", () => {
    const dependencies = [...make("list", 11), ...make("routingRule", 3)]
    const { rows, hiddenCount } = planDependencyRows(dependencies, true)

    expect(rows).toHaveLength(2)
    expect(rows[0]?.items).toHaveLength(11)
    expect(hiddenCount).toBe(0)
  })

  test("пустой список не выдумывает кнопку", () => {
    expect(planDependencyRows([], false)).toEqual({ rows: [], hiddenCount: 0 })
  })
})

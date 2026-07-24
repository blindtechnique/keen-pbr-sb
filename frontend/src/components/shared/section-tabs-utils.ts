export function getMobileTabPartition<T extends { value: string }>(
  tabs: readonly T[],
  value: T["value"],
  visibleLimit = 2
) {
  const visible = tabs.slice(0, visibleLimit)
  const active = tabs.find((tab) => tab.value === value)

  if (
    active &&
    visible.length > 0 &&
    !visible.some((tab) => tab.value === active.value)
  ) {
    visible[visible.length - 1] = active
  }

  const visibleValues = new Set(visible.map((tab) => tab.value))
  return {
    visible,
    overflow: tabs.filter((tab) => !visibleValues.has(tab.value)),
  }
}

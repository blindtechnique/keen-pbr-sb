import { useCallback, useState } from "react"

type Equality<T> = (left: T, right: T) => boolean

export function useSemanticEditSession<T>(
  baseline: T,
  equals: Equality<T> = Object.is
) {
  const [value, setValue] = useState<T>(baseline)
  const isDirty = !equals(value, baseline)
  const reset = useCallback(() => {
    setValue(baseline)
  }, [baseline])

  return {
    value,
    setValue,
    isDirty,
    reset,
  }
}

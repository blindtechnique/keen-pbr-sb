import { useCallback, useState } from "react"

import {
  isSemanticallyDirty,
  type SemanticEquality,
} from "@/lib/semantic-dirty"

export function useSemanticEditSession<T>(
  baseline: T,
  equals: SemanticEquality<T> = Object.is
) {
  const [value, setValue] = useState<T>(baseline)
  const isDirty = isSemanticallyDirty(value, baseline, { equals })
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

export type SemanticEquality<T> = (left: T, right: T) => boolean

export type SemanticDirtyOptions<T, Comparable = T> = {
  equals?: SemanticEquality<Comparable>
  normalize?: (value: T) => Comparable
}

const identity = <T>(value: T) => value

/**
 * Compares the value that would actually be persisted with its baseline.
 *
 * Forms can supply their submit normalizer so representation-only edits
 * (whitespace, omitted defaults, inactive fields) do not leave a false dirty
 * state. This function is deliberately side-effect free: persistence remains
 * an explicit submit action.
 */
export function isSemanticallyDirty<T, Comparable = T>(
  value: T,
  baseline: T,
  options: SemanticDirtyOptions<T, Comparable> = {}
) {
  const normalize =
    options.normalize ??
    (identity as unknown as (candidate: T) => Comparable)
  const equals = options.equals ?? Object.is

  return !equals(normalize(value), normalize(baseline))
}

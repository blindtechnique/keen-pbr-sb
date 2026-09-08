import { semanticJsonEqual } from "@/lib/semantic-json"

/** Keep deliberate local field edits, not untouched values from an old config. */
export function rebaseSettingsDraft<T extends object>(
  previous: T,
  current: T,
  next: T
): T {
  const rebased = { ...next }
  for (const key of Object.keys(current) as (keyof T)[]) {
    if (!semanticJsonEqual(current[key], previous[key])) {
      rebased[key] = current[key]
    }
  }
  return rebased
}

export type GeneralConfigActionStateInput = {
  canSubmit: boolean
  deferredDirty: boolean
  deferredValid: boolean
  isDefaultValue: boolean
  isPending: boolean
}

export type GeneralConfigActionState = {
  cancelDisabled: boolean
  hasChanges: boolean
  saveDisabled: boolean
}

/**
 * TanStack keeps `isPristine=false` after a field has ever been changed.
 * `isDefaultValue` is the semantic deep comparison with the current reset
 * baseline, so restoring a toggle or an ordered list does not leave a no-op
 * save pending.
 */
export function getGeneralConfigActionState({
  canSubmit,
  deferredDirty,
  deferredValid,
  isDefaultValue,
  isPending,
}: GeneralConfigActionStateInput): GeneralConfigActionState {
  const hasChanges = !isDefaultValue || deferredDirty

  return {
    cancelDisabled: isPending || !hasChanges,
    hasChanges,
    saveDisabled: isPending || !hasChanges || !canSubmit || !deferredValid,
  }
}

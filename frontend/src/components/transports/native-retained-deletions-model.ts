import type {
  NdmsNativeRetainedDeletionBlocker,
  NdmsNativeRetainedDeletionDeferredCheck,
} from "@/api/generated/model"
import type {
  NdmsNativeTombstoneForgetArtifactState,
  NdmsNativeTombstoneForgetResult,
  NdmsNativeTombstoneForgetStop,
} from "@/api/native-mutation"
import type { NativeMutationLeaseDisposition } from "@/lib/native-mutation-lock"

export const retainedDeletionBlockerKey = (
  blocker: NdmsNativeRetainedDeletionBlocker
): string => `transports.nativeMutation.forget.blockers.${blocker}`

export const retainedDeletionDeferredCheckKey = (
  check: NdmsNativeRetainedDeletionDeferredCheck
): string => `transports.nativeMutation.forget.deferred.${check}`

export const tombstoneForgetStopKey = (
  stop: NdmsNativeTombstoneForgetStop
): string => `transports.nativeMutation.forget.stops.${stop}`

export const tombstoneForgetOutcomeKey = (
  result: NdmsNativeTombstoneForgetResult
): string => `transports.nativeMutation.forget.outcomes.${result.status}`

export const tombstoneForgetArtifactStateKey = (
  state: NdmsNativeTombstoneForgetArtifactState
): string => `transports.nativeMutation.forget.artifactStates.${state}`

/**
 * Only a typed partial local retirement keeps the forget family latched.
 * Cross-WAL stops hand control to the already existing recovery family; they
 * never dispatch another POST from this model.
 */
export function tombstoneForgetDisposition(
  result: NdmsNativeTombstoneForgetResult
): NativeMutationLeaseDisposition {
  if (result.stop === "import_wal_not_authoritatively_clean") {
    return { state: "redirect_recovery", recovery: "import" }
  }
  if (
    result.stop === "delete_wal_unfinished" ||
    result.stop === "delete_wal_unsafe"
  ) {
    return { state: "redirect_recovery", recovery: "delete" }
  }
  if (result.status === "recovery_required") {
    return { state: "recovery", recovery: "forget" }
  }
  return { state: "clear" }
}

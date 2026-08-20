import type {
  NdmsNativeDeleteResult,
  NdmsNativeImportRecoveryResult,
} from "@/api/native-mutation"
import type { NativeMutationLeaseDisposition } from "@/lib/native-mutation-lock"

export function nativeImportRecoveryDisposition(
  result: NdmsNativeImportRecoveryResult
): NativeMutationLeaseDisposition {
  if (result.status === "no_work" || result.status === "completed") {
    return { state: "clear" }
  }
  if (result.stop === "delete_wal_not_clean") {
    return { state: "redirect_recovery", recovery: "delete" }
  }
  return { state: "recovery", recovery: "import" }
}

export function nativeDeleteRecoveryDisposition(
  result: NdmsNativeDeleteResult
): NativeMutationLeaseDisposition {
  if (
    result.status === "save_acknowledged_unverified" ||
    (result.status === "blocked" && result.stop === "no_delete_transaction")
  ) {
    return { state: "clear" }
  }
  if (result.stop === "import_wal_not_authoritatively_clean") {
    return { state: "redirect_recovery", recovery: "import" }
  }
  return { state: "recovery", recovery: "delete" }
}

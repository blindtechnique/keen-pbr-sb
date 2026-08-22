import { useEffect, useRef, useState } from "react"

import type { NdmsNativeRetainedDeletion } from "@/api/generated/model"
import { postNdmsNativeTombstoneForgetOnce } from "@/api/native-mutation"

/**
 * Retained rollback metadata is an implementation detail. Clean it up in the
 * background and never turn it into a second user-facing deletion workflow.
 * The server still serialises this metadata-only operation with every native
 * mutation and repeats its authoritative absence checks.
 */
export function NativeRetainedDeletions({
  retainedDeletions,
  onInventoryRefresh,
}: {
  readonly retainedDeletions: readonly NdmsNativeRetainedDeletion[]
  readonly onInventoryRefresh: () => Promise<void>
}) {
  const inFlight = useRef(false)
  const attempts = useRef(new Map<string, number>())
  const [pass, setPass] = useState(0)

  useEffect(() => {
    if (inFlight.current) return
    const retained = retainedDeletions.find(
      (candidate) => candidate.forget_candidate
    )
    if (!retained) return

    const key = `${retained.interface_name}:${retained.ownership_revision}`
    const attempt = attempts.current.get(key) ?? 0
    const delay =
      attempt === 0 ? 0 : Math.min(750 * 2 ** Math.min(attempt - 1, 5), 20_000)

    const timeout = window.setTimeout(() => {
      inFlight.current = true
      void postNdmsNativeTombstoneForgetOnce({
        interface_name: retained.interface_name,
        expected_ownership_revision: retained.ownership_revision,
        confirm_interface_name: retained.interface_name,
        rollback_discard_acknowledgement: "permanently_discard_rollback_data",
        foreign_reappearance_acknowledgement:
          "accepted_reappearance_is_foreign",
      })
        .then((result) => {
          if (result.status === "forgotten") {
            attempts.current.delete(key)
          } else {
            attempts.current.set(key, attempt + 1)
          }
        })
        .catch(() => {
          attempts.current.set(key, attempt + 1)
        })
        .finally(async () => {
          await onInventoryRefresh().catch(() => undefined)
          inFlight.current = false
          setPass((value) => value + 1)
        })
    }, delay)

    return () => window.clearTimeout(timeout)
  }, [onInventoryRefresh, pass, retainedDeletions])

  return null
}

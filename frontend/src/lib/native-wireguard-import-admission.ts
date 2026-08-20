import type {
  NdmsInterfaceInventoryResponseRequiredGuardsItem,
  NdmsNativeImportReadiness,
  NdmsNativeImportTargetRange,
  NdmsTunnelInterface,
} from "@/api/generated/model"

const canonicalRange = (range: NdmsNativeImportTargetRange) => ({
  prefix: range.prefix,
  first_index: range.first_index,
  last_index: range.last_index,
})

const rangeKey = (range: NdmsNativeImportTargetRange): string =>
  `${range.prefix}:${range.first_index}:${range.last_index}`

/**
 * Stable, non-secret revision of every fact displayed beside owner consent.
 * It is only a UI revocation key; the bodyless preflight remains authoritative.
 */
export function nativeWireGuardImportAdmissionRevision({
  protectedTransport,
  readiness,
  requiredGuards,
  existingInterfaces,
}: {
  readonly protectedTransport: boolean
  readonly readiness?: NdmsNativeImportReadiness
  readonly requiredGuards: readonly NdmsInterfaceInventoryResponseRequiredGuardsItem[]
  readonly existingInterfaces: readonly NdmsTunnelInterface[]
}): string {
  const canonicalReadiness = readiness
    ? {
        preview_only: readiness.preview_only,
        apply_available: readiness.apply_available,
        operation: readiness.operation,
        request_name: readiness.request_name,
        allocator_range: canonicalRange(readiness.allocator_range),
        eligible_returned_targets: canonicalRange(
          readiness.eligible_returned_targets
        ),
        protected_targets: [...readiness.protected_targets]
          .sort((left, right) => rangeKey(left).localeCompare(rangeKey(right)))
          .map(canonicalRange),
        journal_state: readiness.journal_state,
        reconcile_barrier_state: readiness.reconcile_barrier_state,
        blockers: [...readiness.blockers].sort(),
      }
    : null

  const inventory = existingInterfaces
    .map((entry) => ({
      id: entry.id,
      firmware_interface_name: entry.firmware_interface_name,
      kernel_name: entry.kernel_name ?? null,
      kind: entry.kind,
      role: entry.role,
      owner: entry.owner,
      candidate: entry.management_readiness.candidate,
      identity_stable: entry.management_readiness.identity_stable,
      observed_revision: entry.management_readiness.observed_revision,
      management_blockers: [...entry.management_readiness.blockers].sort(),
    }))
    .sort((left, right) =>
      `${left.firmware_interface_name}\0${left.id}`.localeCompare(
        `${right.firmware_interface_name}\0${right.id}`
      )
    )

  return JSON.stringify({
    protectedTransport,
    readiness: canonicalReadiness,
    requiredGuards: [...requiredGuards].sort(),
    inventory,
  })
}

import { expect, test } from "bun:test"

import { nativeWireGuardImportAdmissionRevision } from "@/lib/native-wireguard-import-admission"
import type {
  NdmsNativeImportReadiness,
  NdmsTunnelInterface,
} from "@/api/generated/model"

const readiness: NdmsNativeImportReadiness = {
  preview_only: true,
  apply_available: false,
  operation: "interface.wireguard.import",
  request_name: "",
  allocator_range: { prefix: "Wireguard", first_index: 0, last_index: 126 },
  eligible_returned_targets: {
    prefix: "Wireguard",
    first_index: 5,
    last_index: 126,
  },
  protected_targets: [
    { prefix: "Wireguard", first_index: 0, last_index: 4 },
  ],
  journal_state: "clean",
  reconcile_barrier_state: "dormant",
  blockers: ["writer_disabled"],
}

const interfaceEntry = (id: string): NdmsTunnelInterface => ({
  id,
  firmware_interface_name: id,
  kernel_name: `n${id.toLowerCase()}`,
  label: `Label ${id}`,
  firmware_type: "Wireguard",
  kind: "wireguard",
  role: "client",
  internal_vpn_server_candidate: false,
  internal_vpn_server_role_confirmation_required: false,
  owner: "keenetic",
  capabilities: {
    can_edit: false,
    can_delete: false,
    can_hide: true,
    backup_required: true,
  },
  management_readiness: {
    candidate: true,
    identity_stable: true,
    observed_revision: `revision-${id}`,
    configuration_snapshot_available: false,
    blockers: [],
  },
})

test("native import admission revision is reorder-stable and complete", () => {
  const first = interfaceEntry("Wireguard5")
  const second = interfaceEntry("Wireguard6")
  const base = nativeWireGuardImportAdmissionRevision({
    protectedTransport: true,
    readiness,
    requiredGuards: ["typed_rci", "ownership_check"],
    existingInterfaces: [first, second],
  })

  expect(
    nativeWireGuardImportAdmissionRevision({
      protectedTransport: true,
      readiness: {
        ...readiness,
        blockers: [...readiness.blockers].reverse(),
        protected_targets: [...readiness.protected_targets].reverse(),
      },
      requiredGuards: ["ownership_check", "typed_rci"],
      existingInterfaces: [second, first],
    })
  ).toBe(base)

  for (const changed of [
    { readiness: { ...readiness, operation: "changed" } },
    {
      readiness: {
        ...readiness,
        eligible_returned_targets: {
          ...readiness.eligible_returned_targets,
          first_index: 6,
        },
      },
    },
    {
      readiness: {
        ...readiness,
        reconcile_barrier_state: "changed" as never,
      },
    },
  ]) {
    expect(
      nativeWireGuardImportAdmissionRevision({
        protectedTransport: true,
        readiness: changed.readiness,
        requiredGuards: ["typed_rci", "ownership_check"],
        existingInterfaces: [first, second],
      })
    ).not.toBe(base)
  }

  expect(
    nativeWireGuardImportAdmissionRevision({
      protectedTransport: true,
      readiness,
      requiredGuards: ["typed_rci", "ownership_check"],
      existingInterfaces: [
        first,
        {
          ...second,
          management_readiness: {
            ...second.management_readiness,
            observed_revision: "changed",
          },
        },
      ],
    })
  ).not.toBe(base)
})

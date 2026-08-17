import { describe, expect, test } from "bun:test"

import {
  buildInternalVpnServiceOptions,
  getInternalVpnServiceProcessClients,
  normalizeInternalVpnServiceOverrides,
  reconcileInternalVpnServiceOverrides,
  removeInternalVpnServiceOverride,
  updateInternalVpnServiceOverride,
} from "../src/lib/internal-vpn-service-policy"

describe("internal VPN service policy", () => {
  test("builds deterministic rows for every pooled Keenetic server kind", () => {
    const options = buildInternalVpnServiceOptions({
      services: [
        service("ndms-service:oc-server", "openconnect", "OpenConnect server"),
        service("ndms-service:sstp-server", "sstp", "SSTP server"),
        service("ndms-crypto-map:VirtualIPServerIKE2", "ikev2", "IKEv2 server"),
        service("ndms-crypto-map:VirtualIPServer", "ikev1", "IKEv1 server"),
        service("ndms-service:l2tp-server", "l2tp", "L2TP server"),
      ],
    })

    expect(options.map((option) => option.kind)).toEqual([
      "l2tp",
      "ikev1",
      "ikev2",
      "sstp",
      "openconnect",
    ])
  })

  test("keeps a persisted missing service visible and removable", () => {
    const options = buildInternalVpnServiceOptions({
      services: [],
      overrides: [
        {
          service_id: "ndms-service:sstp-server",
          process_clients: false,
        },
      ],
    })

    expect(options).toEqual([
      {
        key: "ndms-service:sstp-server",
        serviceId: "ndms-service:sstp-server",
        label: "ndms-service:sstp-server",
        enabled: false,
        sourceCidrs: [],
        missing: true,
      },
    ])
    expect(
      removeInternalVpnServiceOverride({
        serviceId: "ndms-service:sstp-server",
        overrides: [
          {
            service_id: "ndms-service:sstp-server",
            process_clients: false,
          },
        ],
      })
    ).toBeUndefined()
  })

  test("inherits legacy all-ingress and explicit allowlist behavior", () => {
    expect(
      getInternalVpnServiceProcessClients({
        serviceId: "ndms-service:l2tp-server",
        legacyInboundInterfaces: [],
      })
    ).toBe(true)
    expect(
      getInternalVpnServiceProcessClients({
        serviceId: "ndms-service:l2tp-server",
        legacyInboundInterfaces: ["br0"],
      })
    ).toBe(false)
  })

  test("stores only a semantic override and clears dirty state on restore", () => {
    const disabled = updateInternalVpnServiceOverride({
      serviceId: "ndms-service:l2tp-server",
      processClients: false,
      legacyInboundInterfaces: [],
    })
    expect(disabled).toEqual([
      {
        service_id: "ndms-service:l2tp-server",
        process_clients: false,
      },
    ])

    expect(
      updateInternalVpnServiceOverride({
        serviceId: "ndms-service:l2tp-server",
        processClients: true,
        overrides: disabled,
        legacyInboundInterfaces: [],
      })
    ).toBeUndefined()
  })

  test("inherit removes a persisted explicit policy", () => {
    const baseline = [
      {
        service_id: "ndms-service:sstp-server",
        process_clients: false,
      },
    ]

    expect(
      removeInternalVpnServiceOverride({
        serviceId: "ndms-service:sstp-server",
        overrides: baseline,
        baselineOverrides: baseline,
      })
    ).toBeUndefined()
  })

  test("restores the exact baseline after an inbound allowlist round trip", () => {
    const explicitWhileAllowlisted = [
      {
        service_id: "ndms-service:l2tp-server",
        process_clients: true,
      },
    ]

    expect(
      reconcileInternalVpnServiceOverrides({
        overrides: explicitWhileAllowlisted,
        legacyInboundInterfaces: [],
        baselineLegacyInboundInterfaces: [],
      })
    ).toBeUndefined()

    expect(
      reconcileInternalVpnServiceOverrides({
        overrides: explicitWhileAllowlisted,
        legacyInboundInterfaces: ["br0"],
        baselineLegacyInboundInterfaces: [],
      })
    ).toEqual(explicitWhileAllowlisted)
  })

  test("normalizes duplicate service identities without trusting ranges", () => {
    expect(
      normalizeInternalVpnServiceOverrides([
        {
          service_id: " ndms-service:sstp-server ",
          process_clients: true,
        },
        {
          service_id: "ndms-service:sstp-server",
          process_clients: false,
        },
      ])
    ).toEqual([
      {
        service_id: "ndms-service:sstp-server",
        process_clients: false,
      },
    ])
  })
})

function service(
  id: string,
  kind: "l2tp" | "ikev1" | "ikev2" | "sstp" | "openconnect",
  label: string
) {
  return {
    id,
    kind,
    label,
    enabled: true,
    source_cidrs: ["172.16.0.0/24"],
    inventory_revision: "a".repeat(64),
  }
}

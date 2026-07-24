import { describe, expect, test } from "bun:test"

import type {
  HealthResponse,
  RuntimeOutboundState,
} from "../src/api/generated/model"
import { getHeaderHealthTone } from "../src/components/layout/header-health-state"

const healthyService = {
  config_is_draft: false,
  resolver_config_probe_status: "success",
  resolver_config_sync_state: "converged",
  resolver_live_status: "healthy",
  runtime_state: "running",
  status: "running",
} satisfies Partial<HealthResponse> as HealthResponse

const outbound = (
  status: RuntimeOutboundState["status"]
): RuntimeOutboundState =>
  ({
    status,
  }) as RuntimeOutboundState

describe("header health classifier", () => {
  test("keeps loading or unknown data at attention", () => {
    expect(getHeaderHealthTone({})).toBe("attention")
    expect(getHeaderHealthTone({ service: healthyService })).toBe("attention")
  })

  test("reports healthy only for a converged service and healthy outbounds", () => {
    expect(
      getHeaderHealthTone({
        service: healthyService,
        outbounds: [outbound("healthy"), outbound("healthy")],
        statusEvents: "connected",
      })
    ).toBe("healthy")
  })

  test("reports transitions, drafts, stale DNS and uncertain paths as attention", () => {
    expect(
      getHeaderHealthTone({
        service: { ...healthyService, runtime_state: "applying" },
        outbounds: [outbound("healthy")],
      })
    ).toBe("attention")
    expect(
      getHeaderHealthTone({
        service: { ...healthyService, config_is_draft: true },
        outbounds: [outbound("healthy")],
      })
    ).toBe("attention")
    expect(
      getHeaderHealthTone({
        service: {
          ...healthyService,
          resolver_config_sync_state: "stale",
        },
        outbounds: [outbound("healthy")],
      })
    ).toBe("attention")
    expect(
      getHeaderHealthTone({
        service: healthyService,
        outbounds: [outbound("unknown")],
      })
    ).toBe("attention")
    expect(
      getHeaderHealthTone({
        service: healthyService,
        outbounds: [outbound("healthy")],
        statusEvents: "disconnected",
      })
    ).toBe("attention")
  })

  test("gives explicit service, DNS and outbound failures highest priority", () => {
    expect(
      getHeaderHealthTone({
        service: { ...healthyService, runtime_state: "broken" },
        outbounds: [outbound("healthy")],
      })
    ).toBe("failed")
    expect(
      getHeaderHealthTone({
        service: {
          ...healthyService,
          resolver_live_status: "unavailable",
        },
        outbounds: [outbound("healthy")],
      })
    ).toBe("failed")
    expect(
      getHeaderHealthTone({
        service: { ...healthyService, runtime_state: "applying" },
        outbounds: [outbound("unavailable")],
      })
    ).toBe("attention")
    expect(
      getHeaderHealthTone({
        service: healthyService,
        outbounds: [outbound("healthy")],
        serviceQueryFailed: true,
      })
    ).toBe("failed")
  })
})

import { describe, expect, test } from "bun:test"

import type {
  HealthResponse,
  RuntimeOutboundState,
} from "@/api/generated/model"
import {
  collectDashboardAttentionItems,
  dashboardSectionIds,
} from "@/components/overview/system-status-summary-model"

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
    tag: status,
    type: "interface",
    status,
    interfaces: [],
  }) satisfies RuntimeOutboundState

describe("dashboard attention links", () => {
  test("does not invent problems while the initial snapshot is missing", () => {
    expect(collectDashboardAttentionItems({})).toEqual([])
  })

  test("exposes runtime query failures as clickable attention items", () => {
    expect(
      collectDashboardAttentionItems({
        outboundsQueryFailed: true,
        serviceQueryFailed: true,
      })
    ).toEqual([
      {
        id: "service",
        targetId: dashboardSectionIds.service,
        tone: "error",
      },
      {
        id: "outbounds",
        targetId: dashboardSectionIds.outbounds,
        tone: "error",
      },
    ])
  })

  test("returns one compact link for every affected dashboard section", () => {
    expect(
      collectDashboardAttentionItems({
        service: {
          ...healthyService,
          status: "stopped",
          runtime_state: "broken",
          resolver_live_status: "unavailable",
        },
        routingOverall: "degraded",
        outbounds: [outbound("healthy"), outbound("unavailable")],
      })
    ).toEqual([
      {
        id: "service",
        targetId: "dashboard-services",
        tone: "error",
      },
      { id: "dns", targetId: "dashboard-dns", tone: "error" },
      {
        id: "routing",
        targetId: "dashboard-routing",
        tone: "warning",
      },
      {
        id: "outbounds",
        targetId: "dashboard-outbounds",
        tone: "error",
        count: 1,
      },
    ])
  })

  test("classifies transitional states as warnings rather than failures", () => {
    expect(
      collectDashboardAttentionItems({
        service: {
          ...healthyService,
          runtime_state: "applying",
          resolver_config_sync_state: "converging",
        },
        routingOverall: "ok",
        outbounds: [outbound("degraded"), outbound("unknown")],
      })
    ).toEqual([
      {
        id: "service",
        targetId: "dashboard-services",
        tone: "warning",
      },
      { id: "dns", targetId: "dashboard-dns", tone: "warning" },
      {
        id: "outbounds",
        targetId: "dashboard-outbounds",
        tone: "warning",
        count: 2,
      },
    ])
  })

  test("returns no attention links for a healthy runtime", () => {
    expect(
      collectDashboardAttentionItems({
        service: healthyService,
        routingOverall: "ok",
        outbounds: [outbound("healthy")],
      })
    ).toEqual([])
  })
})

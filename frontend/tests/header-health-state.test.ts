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

/**
 * Красный обещает, что что-то не работает. Пока любой упавший маршрут красил
 * индикатор, обещание нарушалось: туннель, к которому не привязан ни один
 * список, и участник группы, которого группа уже заменила, ничего не ломают.
 */
describe("header health: упавший маршрут против осиротевшего списка", () => {
  const tagged = (
    tag: string,
    status: RuntimeOutboundState["status"]
  ): RuntimeOutboundState => ({ tag, status }) as RuntimeOutboundState

  test("упавший маршрут без списков — внимание, а не красный", () => {
    expect(
      getHeaderHealthTone({
        service: healthyService,
        outbounds: [tagged("vpn_main", "healthy"), tagged("spare", "unavailable")],
        routeRules: [{ outbound: "vpn_main", list: ["streaming"] }],
        statusEvents: "connected",
      })
    ).toBe("attention")
  })

  test("упавший маршрут со списком — красный: списку некуда идти", () => {
    expect(
      getHeaderHealthTone({
        service: healthyService,
        outbounds: [tagged("vpn_main", "unavailable")],
        routeRules: [{ outbound: "vpn_main", list: ["streaming"] }],
        statusEvents: "connected",
      })
    ).toBe("failed")
  })

  test("выключенное правило не делает упавший маршрут поломкой", () => {
    expect(
      getHeaderHealthTone({
        service: healthyService,
        outbounds: [tagged("vpn_main", "unavailable")],
        routeRules: [
          { outbound: "vpn_main", list: ["streaming"], enabled: false },
        ],
        statusEvents: "connected",
      })
    ).toBe("attention")
  })

  // Намеренно остановленный транспорт вырезается из списка ещё до классификатора.
  test("маршрута нет в списке — индикатор не краснеет", () => {
    expect(
      getHeaderHealthTone({
        service: healthyService,
        outbounds: [tagged("vpn_main", "healthy")],
        routeRules: [{ outbound: "gone", list: ["streaming"] }],
        statusEvents: "connected",
      })
    ).toBe("healthy")
  })

  // Без правил безобидность падения доказать нечем — старое строгое поведение.
  test("без правил любой упавший маршрут остаётся красным", () => {
    expect(
      getHeaderHealthTone({
        service: healthyService,
        outbounds: [tagged("spare", "unavailable")],
        statusEvents: "connected",
      })
    ).toBe("failed")
  })
})

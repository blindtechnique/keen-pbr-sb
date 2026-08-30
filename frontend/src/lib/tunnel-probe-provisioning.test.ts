import { describe, expect, it } from "bun:test"

import type { ConfigObject } from "@/api/generated/model/configObject"
import {
  TUNNEL_PROBE_DEFAULT_LIST,
  provisionTunnelProbe,
  tunnelProbeListFile,
} from "@/lib/tunnel-probe-provisioning"

const bareConfig = (): ConfigObject => ({
  outbounds: [
    { tag: "wan", type: "table", table: 254 },
    { tag: "tr_9786265a", type: "interface", interface: "kpbr9786265a" },
  ],
})

describe("tunnel probe provisioning", () => {
  it("makes one click enough: list, file and rule all appear", () => {
    const result = provisionTunnelProbe(bareConfig(), {
      enabled: true,
      outbound: "",
      list: "",
    })

    expect(result.resolved.list).toBe(TUNNEL_PROBE_DEFAULT_LIST)
    // The first outbound with an interface: a probe leg is pinned to a device,
    // so "wan" as a table outbound cannot carry one.
    expect(result.resolved.outbound).toBe("tr_9786265a")

    const list = result.config.lists?.[TUNNEL_PROBE_DEFAULT_LIST]
    expect(list?.file).toBe(tunnelProbeListFile(TUNNEL_PROBE_DEFAULT_LIST))
    expect(result.createdList).toBe(true)

    const rule = result.config.route?.rules?.find((entry) =>
      entry.list?.includes(TUNNEL_PROBE_DEFAULT_LIST)
    )
    expect(rule?.outbound).toBe("tr_9786265a")
    expect(rule?.enabled).toBe(true)
    expect(result.createdRule).toBe(true)
  })

  it("routes confirmed hosts through the tunnel that was measured", () => {
    // The invariant worth protecting: proving that a tunnel fixes a host and
    // then sending the host through a different one would mean the measurement
    // justified nothing.
    const result = provisionTunnelProbe(bareConfig(), {
      enabled: true,
      outbound: "tr_9786265a",
      list: "",
    })

    const rule = result.config.route?.rules?.[0]
    expect(rule?.outbound).toBe(result.resolved.outbound)
  })

  it("gives an existing list a file without touching what it already holds", () => {
    const config: ConfigObject = {
      ...bareConfig(),
      lists: {
        found_blocked: {
          display_name: "Найдено пробой",
          domains: ["thumbnails.libretro.com"],
          ttl_ms: 7200000,
        },
      },
    }

    const result = provisionTunnelProbe(config, {
      enabled: true,
      outbound: "tr_9786265a",
      list: "found_blocked",
    })

    const list = result.config.lists?.found_blocked
    expect(list?.file).toBe(tunnelProbeListFile("found_blocked"))
    // Every source of a list is read together, so the inline domains stay.
    expect(list?.domains).toEqual(["thumbnails.libretro.com"])
    expect(result.addedFile).toBe(true)
    expect(result.createdList).toBe(false)
  })

  it("leaves an already-routed list alone instead of adding a second rule", () => {
    const config: ConfigObject = {
      ...bareConfig(),
      lists: { found_blocked: { file: "/opt/etc/keen-pbr/found_blocked.lst" } },
      route: {
        rules: [
          { id: "naydeno_proboy", list: ["found_blocked"], outbound: "awg_bound" },
        ],
      },
    }

    const result = provisionTunnelProbe(config, {
      enabled: true,
      outbound: "tr_9786265a",
      list: "found_blocked",
    })

    expect(result.config.route?.rules).toHaveLength(1)
    expect(result.createdRule).toBe(false)
    expect(result.addedFile).toBe(false)
  })

  it("creates nothing at all when the switch is off", () => {
    const before = bareConfig()

    const result = provisionTunnelProbe(before, {
      enabled: false,
      outbound: "",
      list: "",
    })

    expect(result.config).toBe(before)
    expect(result.createdList).toBe(false)
    expect(result.createdRule).toBe(false)
    // Nothing is invented for a switch that is off, including a list name.
    expect(result.resolved.list).toBe("")
  })

  it("creates nothing when no outbound can carry a probe", () => {
    // A rule pointing nowhere would be worse than no rule; the daemon refuses
    // the pass and says which piece is missing.
    const config: ConfigObject = {
      outbounds: [{ tag: "wan", type: "table", table: 254 }],
    }

    const result = provisionTunnelProbe(config, {
      enabled: true,
      outbound: "",
      list: "",
    })

    expect(result.resolved.outbound).toBe("")
    expect(result.config.lists).toBeUndefined()
    expect(result.createdRule).toBe(false)
  })

  it("does not collide with a rule that already uses the id", () => {
    const config: ConfigObject = {
      ...bareConfig(),
      route: { rules: [{ id: "tunnel_probe", list: ["other"], outbound: "wan" }] },
    }

    const result = provisionTunnelProbe(config, {
      enabled: true,
      outbound: "tr_9786265a",
      list: "",
    })

    const ids = result.config.route?.rules?.map((rule) => rule.id)
    expect(new Set(ids).size).toBe(ids?.length)
  })
})

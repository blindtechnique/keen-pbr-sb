import { describe, expect, test } from "bun:test"

import type { CatalogSetupPreviewResponse } from "../src/api/generated/model"
import { getCatalogSetupInstallState } from "../src/pages/catalog-setup-api"

function preview(
  installed: readonly boolean[],
  policyChanges = false
): CatalogSetupPreviewResponse {
  return {
    base_revision: "a".repeat(64),
    candidate_revision: "b".repeat(64),
    preview_token: "c".repeat(64),
    requires_warning_acceptance: false,
    summary: {
      mode: "outbound",
      lists: installed.map((alreadyInstalled, index) => ({
        preset_id: `preset-${index}`,
        technical_id: `preset_${index}`,
        display_name: `Preset ${index}`,
        already_installed: alreadyInstalled,
        url_backed: true,
        has_inline_domains: false,
        has_inline_cidrs: false,
      })),
      route_rule: policyChanges
        ? {
            technical_id: "catalog_policy",
            display_name: "Policy",
            outbound: "proxy",
            insertion_index: 0,
            blocking: false,
          }
        : undefined,
    },
    warnings: [],
  }
}

describe("catalog setup preview install state", () => {
  test("distinguishes existing presets from lists still to create", () => {
    const state = getCatalogSetupInstallState(preview([true, false, true]))

    expect(state.installed.map((list) => list.preset_id)).toEqual([
      "preset-0",
      "preset-2",
    ])
    expect(state.pending.map((list) => list.preset_id)).toEqual(["preset-1"])
    expect(state.allInstalled).toBe(false)
    expect(state.noChanges).toBe(false)
  })

  test("only marks fully installed and fully covered selections as no-op", () => {
    const covered = getCatalogSetupInstallState(preview([true, true]))
    expect(covered.allInstalled).toBe(true)
    expect(covered.noChanges).toBe(true)

    const missingPolicy = getCatalogSetupInstallState(
      preview([true, true], true)
    )
    expect(missingPolicy.allInstalled).toBe(true)
    expect(missingPolicy.noChanges).toBe(false)

    const empty = getCatalogSetupInstallState(preview([]))
    expect(empty.allInstalled).toBe(false)
    expect(empty.noChanges).toBe(false)
  })

  test("counts an automatically created DNS server as a policy change", () => {
    const result = preview([true, true])
    result.summary.dns_server = {
      technical_id: "dns_cloudflare_proxy",
      display_name: "Cloudflare через Proxy",
      address: "1.1.1.1",
      detour: "proxy",
      created: true,
    }

    const state = getCatalogSetupInstallState(result)
    expect(state.allInstalled).toBe(true)
    expect(state.noChanges).toBe(false)
  })
})

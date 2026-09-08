import { describe, expect, test } from "bun:test"
import { readFileSync } from "node:fs"
import { renderToStaticMarkup } from "react-dom/server"

import type { ConfigObject } from "../src/api/generated/model/configObject"
import { DataTable } from "../src/components/shared/data-table"
import { EditDeleteActions } from "../src/components/shared/edit-delete-actions"
import {
  buildUpdatedConfigForOutboundsDelete,
  getOutboundDeleteImpact,
} from "../src/pages/outbounds-utils"

const config: ConfigObject = {
  outbounds: [
    { tag: "vpn_a", type: "interface", interface: "nwg1" },
    { tag: "vpn_b", type: "interface", interface: "nwg2" },
    { tag: "wan", type: "table", table: 254 },
    {
      tag: "vpn_group",
      type: "urltest",
      outbound_groups: [{ outbounds: ["vpn_a", "vpn_b"] }],
    },
  ],
}

describe("outbound group row deletion", () => {
  test("offers shared VPN edit/delete actions only for groups and reuses the confirmation pipeline", () => {
    const source = readFileSync(
      new URL("../src/pages/outbounds-page.tsx", import.meta.url),
      "utf8"
    )
    expect(source).toMatch(
      /item\.type === "urltest" \? \(\s*<EditDeleteActions/
    )
    expect(source).toContain("deleteDisabled={configMutationPending}")
    expect(source).toContain('deleteTitle={t("common.delete")}')
    expect(source).toContain("onDelete={() => requestDelete([item.id])}")
    expect(source).toContain(
      "requestDelete(outboundSelection.selectedIds, true)"
    )
    expect(source).toContain("onClick: () => probeMutation.mutate(item.id)")

    const requestHandler = source.slice(
      source.indexOf("const requestDelete ="),
      source.indexOf("const handleBulkDelete =")
    )
    expect(requestHandler).toContain("filterDeletableOutboundTags(")
    expect(requestHandler).toContain(
      "getOutboundDeleteImpact(loadedConfig, tags)"
    )
    expect(requestHandler).toContain("setDeleteRequest(request)")
    expect(requestHandler).not.toContain(".mutate(")
    expect(source).toContain("<DeleteImpactDialog")
    expect(source).toContain("onConfirm={confirmDelete}")
    expect(source).toMatch(
      /buildUpdatedConfigForOutboundsDelete\(\s*loadedConfig,\s*deleteRequest\.tags/
    )
  })

  test("renders the same accessible red trash button in desktop and mobile rows", () => {
    const html = renderToStaticMarkup(
      <DataTable
        headers={["Group", "Actions"]}
        rows={[
          [
            "VPN group",
            <EditDeleteActions
              deleteTitle="Delete group"
              editTitle="Edit group"
              key="actions"
              onDelete={() => undefined}
              onEdit={() => undefined}
            />,
          ],
        ]}
      />
    )
    const buttons = [
      ...html.matchAll(/<button\b[^>]*aria-label="Delete group"[^>]*>/g),
    ]
    expect(buttons).toHaveLength(2)
    for (const [button] of buttons) {
      expect(button).toContain("keen-row-action--danger")
      expect(button).toContain("size-8")
      expect(button).toContain('title="Delete group"')
      expect(button).toContain('type="button"')
    }
    expect(html).toContain("md:block")
    expect(html).toContain("md:hidden")
  })

  test("removes an unused group without deleting or changing its member VPNs", () => {
    const original = structuredClone(config)
    expect(
      getOutboundDeleteImpact(config, ["vpn_group"]).deletedOutboundTags
    ).toEqual(["vpn_group"])
    const next = buildUpdatedConfigForOutboundsDelete(config, ["vpn_group"])
    expect(next.outbounds).toEqual(config.outbounds?.slice(0, 3))
    expect(config).toEqual(original)
  })

  test("retains the existing dependency cleanup without cascading into member VPNs", () => {
    const inUse: ConfigObject = {
      ...config,
      outbounds: [
        ...(config.outbounds ?? []),
        {
          tag: "parent_group",
          type: "urltest",
          outbound_groups: [{ outbounds: ["vpn_group", "vpn_b"] }],
        },
      ],
      route: { rules: [{ outbound: "vpn_group" }, { outbound: "vpn_a" }] },
      dns: { servers: [{ tag: "dns", type: "udp", detour: "vpn_group" }] },
    }
    const original = structuredClone(inUse)
    const impact = getOutboundDeleteImpact(inUse, ["vpn_group"])
    expect(impact.deletedOutboundTags).toEqual(["vpn_group"])
    expect(impact.routeRuleIndexes).toEqual([0])
    expect(impact.dnsServerDetours).toEqual(["dns"])
    expect(impact.urltestMemberships).toEqual([
      {
        outboundTag: "parent_group",
        groupIndex: 0,
        removedTags: ["vpn_group"],
      },
    ])

    const next = buildUpdatedConfigForOutboundsDelete(inUse, ["vpn_group"])
    expect(next.outbounds?.slice(0, 3)).toEqual(config.outbounds?.slice(0, 3))
    expect(next.outbounds?.at(-1)?.outbound_groups).toEqual([
      { outbounds: ["vpn_b"] },
    ])
    expect(next.route?.rules).toEqual([{ outbound: "vpn_a" }])
    expect(next.dns?.servers?.[0]).not.toHaveProperty("detour")
    expect(inUse).toEqual(original)
  })
})

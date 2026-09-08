import { describe, expect, spyOn, test } from "bun:test"
import { readFileSync } from "node:fs"

import { postTransportConfig } from "../src/api/generated/keen-api"
import { postNdmsNativeDeleteOnce } from "../src/api/native-mutation"

const transportsPage = readFileSync(
  new URL("../src/pages/transports-page.tsx", import.meta.url),
  "utf8"
)
const nativeDelete = readFileSync(
  new URL(
    "../src/components/transports/native-interface-delete-dialog.tsx",
    import.meta.url
  ),
  "utf8"
)

describe("linked VPN deletion uses one backend operation", () => {
  test("neither trash action stages, saves, or restores the visible config", () => {
    for (const source of [transportsPage, nativeDelete]) {
      expect(source).not.toContain("postConfig(")
      expect(source).not.toContain("postConfigSave")
      expect(source).not.toContain("prepareLinkedRouteRemoval")
      expect(source).not.toContain("restoreLinkedRoute")
    }
    expect(transportsPage).not.toContain("routeDeleteMutation")
    expect(transportsPage).not.toContain("transports.routeStagedForDelete")
    expect(transportsPage).not.toContain(
      "transports.deleteTunnelAfterRouteFailed"
    )
    expect(transportsPage).toMatch(
      /configMutation\.mutate\(\{\s*data: \{\s*operation: TransportConfigOperationOperation\.delete,\s*tag: deleting\.tag,/
    )
  })

  test("preserves the existing confirmation impact and native dependency warning", () => {
    expect(transportsPage).toContain("<DeleteImpactDialog")
    expect(transportsPage).toContain("getOutboundDeleteImpactItems(")
    expect(transportsPage).toContain("getOutboundDeleteImpact(keenConfig,")
    expect(transportsPage).toContain(
      "summarizeNativeDeleteDependencies(dependencies)"
    )
    expect(transportsPage).toContain(
      't("transports.nativeMutation.deleteDialog.inUse",'
    )
    expect(transportsPage).toContain(
      "<OperationErrorMessage error={mutationError} />"
    )
  })

  test("native success follows the terminal backend result and refresh is nonblocking", () => {
    const request = nativeDelete.indexOf("await postNdmsNativeDeleteOnce(")
    const terminal = nativeDelete.indexOf(
      'if (result.status === "save_acknowledged_unverified")'
    )
    const success = nativeDelete.indexOf("toast.success(")
    expect(request).toBeGreaterThan(-1)
    expect(terminal).toBeGreaterThan(request)
    expect(success).toBeGreaterThan(terminal)
    expect(nativeDelete).toContain('if (result.status === "recovery_required")')
    expect(nativeDelete).toContain("void onInventoryRefresh().catch(")
    expect(nativeDelete).not.toContain("await onInventoryRefresh()")
  })

  test("sing-box delete sends only its stable tag in one request", async () => {
    const request = { operation: "delete" as const, tag: "subscription_vpn" }
    const fetchSpy = spyOn(globalThis, "fetch").mockResolvedValue(
      Response.json({ status: "deleted", tag: request.tag })
    )
    try {
      const response = await postTransportConfig(request)
      expect(response.data).toEqual({ status: "deleted", tag: request.tag })
      expect(fetchSpy).toHaveBeenCalledTimes(1)
      expect(fetchSpy).toHaveBeenCalledWith(
        "/api/transports/config",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify(request),
        })
      )
    } finally {
      fetchSpy.mockRestore()
    }
  })

  test("a backend refusal is not followed by a client config replay", async () => {
    const fetchSpy = spyOn(globalThis, "fetch").mockResolvedValue(
      Response.json({ error: "VPN is used by a group" }, { status: 409 })
    )
    try {
      await expect(
        postTransportConfig({ operation: "delete", tag: "subscription_vpn" })
      ).rejects.toMatchObject({ status: 409 })
      expect(fetchSpy).toHaveBeenCalledTimes(1)
    } finally {
      fetchSpy.mockRestore()
    }
  })

  test("native delete sends the existing identity contract without route snapshots", async () => {
    const request = {
      interface_name: "Wireguard5",
      expected_ownership_revision: `ndms-native-owner-v3-${"a".repeat(64)}`,
      confirm_label: "Wireguard5",
    }
    const terminal = {
      status: "save_acknowledged_unverified",
      stop: "none",
      external_writer_race_excluded: false,
      external_writer_race_accepted: true,
      global_save_scope_acknowledged: true,
      delete_perform_started: false,
      save_perform_started: false,
      request_may_have_been_dispatched: false,
      system_configuration_save_acknowledged: false,
      ownership_tombstone_durable: true,
      rollback_snapshot_retained: true,
      phase: "cleanup",
      interface_name: request.interface_name,
      kind: "wireguard",
    }
    const fetchSpy = spyOn(globalThis, "fetch").mockResolvedValue(
      Response.json(terminal)
    )
    try {
      expect((await postNdmsNativeDeleteOnce(request)).status).toBe(
        terminal.status
      )
      expect(fetchSpy).toHaveBeenCalledTimes(1)
      expect(fetchSpy).toHaveBeenCalledWith(
        "/api/system/ndms/interfaces/remove",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify(request),
        })
      )
    } finally {
      fetchSpy.mockRestore()
    }
  })
})

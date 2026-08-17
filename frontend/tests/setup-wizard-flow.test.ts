import { describe, expect, test } from "bun:test"

import type {
  CatalogSetupIntent,
  CatalogSetupPreviewResponse,
  TransportConfigApplyRequest,
} from "../src/api/generated/model"
import {
  createSetupWizardTransport,
  previewSetupWizardCatalog,
  SetupWizardVisibleDraftError,
} from "../src/pages/setup-wizard-flow"

const intent: CatalogSetupIntent = {
  selections: [{ preset_id: "whatsapp", display_name: "WhatsApp" }],
  mode: "outbound",
  outbound_tag: "vless2",
  dns_mode: "automatic",
}

const preview: CatalogSetupPreviewResponse = {
  base_revision: "a".repeat(64),
  candidate_revision: "b".repeat(64),
  preview_token: "c".repeat(64),
  requires_warning_acceptance: false,
  summary: {
    mode: "outbound",
    lists: [],
  },
  warnings: [],
}

describe("setup wizard transaction flow", () => {
  test("creates the transport and linked route with one atomic request", async () => {
    const requests: TransportConfigApplyRequest[] = []

    const result = await createSetupWizardTransport(
      {
        displayName: "  Primary VLESS  ",
        existingInterfaces: ["vless1"],
        existingTags: ["vless1"],
        link: "  vless://example  ",
      },
      {
        applyTransport: async (request) => {
          requests.push(request)
        },
      }
    )

    expect(requests).toHaveLength(1)
    expect(requests[0]).toEqual({
      operation: "create",
      transport: {
        tag: "vless2",
        interface: "vless2",
        type: "sing-box",
        link: "vless://example",
        display_name: "Primary VLESS",
        auto_start: true,
      },
      linked_outbound: {
        mode: "ensure",
        display_name: "Primary VLESS",
      },
    })
    expect(result.outboundTag).toBe(requests[0]?.transport.tag)
    expect(result.request).toBe(requests[0])
    expect(result.request).not.toHaveProperty("outbounds")
  })

  test("propagates an atomic conflict without a fallback config write", async () => {
    const calls: string[] = []
    const conflict = {
      status: 409,
      message: "configuration changed concurrently",
    }

    await expect(
      createSetupWizardTransport(
        {
          displayName: "Primary",
          existingInterfaces: [],
          existingTags: [],
          link: "vless://example",
        },
        {
          applyTransport: async () => {
            calls.push("atomic-apply")
            throw conflict
          },
        }
      )
    ).rejects.toEqual(conflict)

    expect(calls).toEqual(["atomic-apply"])
  })

  test("reloads an active config before forwarding the exact preview intent", async () => {
    const calls: string[] = []
    let receivedIntent: CatalogSetupIntent | undefined

    const result = await previewSetupWizardCatalog(intent, {
      reloadActiveConfig: async () => {
        calls.push("reload")
        return { isDraft: false }
      },
      previewCatalog: async (value) => {
        calls.push("preview")
        receivedIntent = value
        return preview
      },
    })

    expect(calls).toEqual(["reload", "preview"])
    expect(receivedIntent).toBe(intent)
    expect(result).toBe(preview)
  })

  test("never previews on top of a visible draft", async () => {
    let previewCalls = 0

    await expect(
      previewSetupWizardCatalog(intent, {
        reloadActiveConfig: async () => ({ isDraft: true }),
        previewCatalog: async () => {
          previewCalls += 1
          return preview
        },
      })
    ).rejects.toBeInstanceOf(SetupWizardVisibleDraftError)

    expect(previewCalls).toBe(0)
  })

  test("page has no legacy full-config or second transport mutation path", async () => {
    const source = await Bun.file(
      new URL("../src/pages/setup-wizard-page.tsx", import.meta.url)
    ).text()

    expect(source).not.toMatch(/\bpostConfig\b/)
    expect(source).not.toMatch(/\bpostTransportConfig\b/)
    expect(source).not.toContain("useApplyConfigMutation")
    expect(source).not.toContain("makeTechnicalId")
    expect(source).toContain("preview.requires_warning_acceptance")
    expect(source).toContain(
      "getCatalogSetupInstallState(nextPreview).noChanges"
    )
    expect(source).toContain("applyCatalogSelectionToggle")
  })
})

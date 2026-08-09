import { describe, expect, test } from "bun:test"

import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"
import {
  getWhatsAppTcpResetSourcesInput,
  getWhatsAppTcpResetSourcesIssue,
  parseWhatsAppTcpResetSourcesInput,
  withWhatsAppTcpResetSources,
} from "../src/lib/whatsapp-tcp-reset-sources"

describe("experimental WhatsApp TCP reset sources", () => {
  test("round-trips a bounded per-device list and keeps an empty list disabled", () => {
    expect(
      parseWhatsAppTcpResetSourcesInput("192.168.1.44, 192.168.1.45\n10.10.0.2")
    ).toEqual(["192.168.1.44", "192.168.1.45", "10.10.0.2"])
    expect(
      getWhatsAppTcpResetSourcesInput({
        experimental_whatsapp_tcp_reset_sources: [
          "192.168.1.44",
          "192.168.1.45",
        ],
      })
    ).toBe("192.168.1.44\n192.168.1.45")
    expect(getWhatsAppTcpResetSourcesInput(undefined)).toBe("")
    expect(withWhatsAppTcpResetSources({ ipv6_enabled: true }, "")).toEqual({
      experimental_whatsapp_tcp_reset_sources: [],
      ipv6_enabled: true,
    })
  })

  test("rejects broad, duplicate, reserved, and oversized source selections", () => {
    expect(getWhatsAppTcpResetSourcesIssue("192.168.1.0/24")).toEqual({
      kind: "invalid",
      value: "192.168.1.0/24",
    })
    expect(getWhatsAppTcpResetSourcesIssue("224.0.0.1")).toEqual({
      kind: "invalid",
      value: "224.0.0.1",
    })
    expect(
      getWhatsAppTcpResetSourcesIssue("192.168.1.44, 192.168.1.44")
    ).toEqual({ kind: "duplicate", value: "192.168.1.44" })
    expect(
      getWhatsAppTcpResetSourcesIssue(
        Array.from({ length: 9 }, (_, index) => `192.168.1.${index + 1}`).join(
          ","
        )
      )
    ).toEqual({ count: 9, kind: "too_many" })
    expect(getWhatsAppTcpResetSourcesIssue("192.168.1.44\n10.10.0.2")).toBe(
      null
    )
  })

  test("warns about shared Meta traffic and the iptables-only boundary", () => {
    for (const translation of [enTranslation, ruTranslation]) {
      const advanced = translation.pages.settings.advanced
      expect(advanced.whatsappTcpResetSourcesWarningTitle).toContain(
        "Instagram"
      )
      expect(advanced.whatsappTcpResetSourcesWarningTitle).toContain("iptables")
      expect(advanced.whatsappTcpResetSourcesWarningDescription).toContain(
        "Meta"
      )
    }
  })
})

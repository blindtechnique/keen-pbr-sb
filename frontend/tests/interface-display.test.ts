import { describe, expect, test } from "bun:test"

import { buildInterfaceDisplayNameIndex } from "../src/hooks/use-interface-display-names"
import { resolveInterfaceDisplayName } from "../src/hooks/use-interface-names"

describe("interface display names", () => {
  test("uses the NDMS label as the primary interface name", () => {
    expect(
      resolveInterfaceDisplayName(
        {
          nwg2: {
            label: "Домашний AWG",
          },
        },
        "nwg2"
      )
    ).toBe("Домашний AWG")
  })

  test("keeps the kernel name when NDMS has no useful label", () => {
    expect(resolveInterfaceDisplayName({}, "nwg2")).toBe("nwg2")
    expect(
      resolveInterfaceDisplayName({ nwg2: { label: "   " } }, "nwg2")
    ).toBe("nwg2")
  })

  test("prefers a managed transport alias and keeps the technical identity", () => {
    const names = buildInterfaceDisplayNameIndex(
      {
        nwg2: {
          label: "Имя из NDMS",
        },
      },
      [
        {
          tag: "vless1",
          display_name: "Основной VLESS",
          type: "sing-box",
          interface: "vless1",
          state: "up",
          desired_up: true,
          updated_at: "2026-07-28T00:00:00Z",
        },
        {
          tag: "native_awg",
          display_name: "Домашний AWG",
          type: "native",
          interface: "nwg2",
          state: "up",
          desired_up: true,
          updated_at: "2026-07-28T00:00:00Z",
        },
      ]
    )

    expect(resolveInterfaceDisplayName(names, "vless1")).toBe("Основной VLESS")
    expect(resolveInterfaceDisplayName(names, "nwg2")).toBe("Домашний AWG")
    expect(resolveInterfaceDisplayName(names, "unknown0")).toBe("unknown0")
  })
})

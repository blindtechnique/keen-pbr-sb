import { expect, test } from "bun:test"
import { parseUpdateTransport } from "@/components/settings/software-update-transport"

test("update transport preserves an explicit ordinary path and friendly names", () => {
  expect(
    parseUpdateTransport({
      outbound: "",
      options: [{ tag: "vpn", name: "My VPN" }],
      options_available: true,
    })
  ).toEqual({
    outbound: "",
    options: [{ tag: "vpn", name: "My VPN" }],
    options_available: true,
  })
})

test("a removed saved VPN stays selected instead of silently becoming the router path", () => {
  expect(
    parseUpdateTransport({
      outbound: "removed",
      options: [],
      options_available: true,
    }).outbound
  ).toBe("removed")
})

test("unavailable discovery preserves the selected VPN and allows explicit ordinary routing", () => {
  for (const outbound of ["group", ""]) {
    expect(
      parseUpdateTransport({ outbound, options: [], options_available: false })
    ).toEqual({ outbound, options: [], options_available: false })
  }
})

test("update transport rejects malformed and duplicate choices", () => {
  for (const value of [
    null,
    {},
    { outbound: "", options: [] },
    { outbound: "", options: [], options_available: "false" },
    { outbound: "", options: [null], options_available: true },
    { outbound: "bad;tag", options: [], options_available: true },
    {
      outbound: "",
      options: [{ tag: "vpn", name: {} }],
      options_available: true,
    },
    {
      outbound: "group",
      options: [{ tag: "vpn", name: "My VPN" }],
      options_available: false,
    },
    {
      outbound: "",
      options_available: true,
      options: [
        { tag: "vpn", name: "A" },
        { tag: "vpn", name: "B" },
      ],
    },
  ]) {
    expect(() => parseUpdateTransport(value)).toThrow()
  }
})

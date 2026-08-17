import { describe, expect, test } from "bun:test"

import { excludeIngressServerInterfaces } from "../src/lib/native-interfaces"

const runtime = [
  { name: "nwg0" },
  { name: "nwg3" },
  { name: "br0" },
  { name: "ppp0" },
]

describe("interfaces offered as a route target", () => {
  test("an interface the firmware calls a server is not offered", () => {
    expect(
      excludeIngressServerInterfaces(runtime, [
        { kernel_name: "nwg0", role: "server" },
        { kernel_name: "nwg3", role: "client" },
      ])
    ).toEqual([{ name: "nwg3" }, { name: "br0" }, { name: "ppp0" }])
  })

  // Туннели sing-box в инвентаре прошивки не значатся вовсе. Фильтр «показывать
  // только знакомое» убрал бы как раз их — то есть то, ради чего маршрут и
  // создаётся.
  test("an interface the firmware does not know about stays", () => {
    expect(
      excludeIngressServerInterfaces([{ name: "hy1" }], [
        { kernel_name: "nwg0", role: "server" },
      ])
    ).toEqual([{ name: "hy1" }])
  })

  test("with no inventory nothing is hidden", () => {
    expect(excludeIngressServerInterfaces(runtime, [])).toEqual(runtime)
  })

  test("a server record without a kernel name cannot hide anything", () => {
    expect(
      excludeIngressServerInterfaces(runtime, [
        { kernel_name: null, role: "server" },
      ])
    ).toEqual(runtime)
  })
})

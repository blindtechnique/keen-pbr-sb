import { describe, expect, it } from "bun:test"

import { kernelInterfaceKind } from "../src/lib/kernel-interface-kind"

// Словарь описывает только то, что имя ядра действительно доказывает.
// Кейсы сняты с реального списка интерфейсов Keenetic (MT798x).
describe("kernelInterfaceKind", () => {
  it("recognises the common Keenetic kernel names", () => {
    expect(kernelInterfaceKind("br0")).toBe("bridge")
    expect(kernelInterfaceKind("br2")).toBe("bridge")
    expect(kernelInterfaceKind("eth2")).toBe("ethernet")
    expect(kernelInterfaceKind("eth0.1")).toBe("ethernet")
    expect(kernelInterfaceKind("apcli0")).toBe("wisp")
    expect(kernelInterfaceKind("apclii0")).toBe("wisp")
    expect(kernelInterfaceKind("ra0")).toBe("wifiAp")
    expect(kernelInterfaceKind("rai0")).toBe("wifiAp")
    expect(kernelInterfaceKind("rax0")).toBe("wifiAp")
    expect(kernelInterfaceKind("nwg2")).toBe("firmwareWg")
    expect(kernelInterfaceKind("wg0")).toBe("wireguard")
    expect(kernelInterfaceKind("tun0")).toBe("tun")
    expect(kernelInterfaceKind("ppp0")).toBe("ppp")
    expect(kernelInterfaceKind("kpbr85f462c5")).toBe("keenPbr")
  })

  it("marks plumbing interfaces as service ones", () => {
    for (const name of ["lo", "dummy0", "ifb0", "teql0", "sit0", "ip6tnl0"]) {
      expect(kernelInterfaceKind(name)).toBe("service")
    }
  })

  // Неизвестное имя не получает выдуманного описания: молчание честнее догадки.
  it("stays silent for names it cannot prove", () => {
    expect(kernelInterfaceKind("foo0")).toBeUndefined()
    expect(kernelInterfaceKind("")).toBeUndefined()
    expect(kernelInterfaceKind("ethx")).toBeUndefined()
    // Похожие, но не те: nwg без номера, wg с суффиксом.
    expect(kernelInterfaceKind("nwg")).toBeUndefined()
    expect(kernelInterfaceKind("wgx1")).toBeUndefined()
  })
})

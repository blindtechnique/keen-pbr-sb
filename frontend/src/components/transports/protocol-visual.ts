export type ProtocolVisualKind =
  | "vless"
  | "vmess"
  | "hysteria1"
  | "hysteria2"
  | "tuic"
  | "trojan"
  | "shadowsocks"
  | "anytls"
  | "naive"
  | "wireguard"
  | "amneziawg"
  | "wireguard_ambiguous"
  | "openvpn"
  | "ipsec"
  | "l2tp"
  | "sstp"
  | "openconnect"
  | "socks"
  | "http"
  | "freeturn"
  | "wdtt"
  | "unknown"

export function normalizeProtocolVisualKind(
  protocol: string | null | undefined
): ProtocolVisualKind {
  const value = protocol
    ?.trim()
    .toLowerCase()
    .replaceAll(/[\s_./-]+/g, "")

  if (!value) return "unknown"
  if (value === "vless") return "vless"
  if (value === "vmess") return "vmess"
  if (value === "hysteria" || value === "hysteria1" || value === "hy1") {
    return "hysteria1"
  }
  if (value === "hysteria2" || value === "hy2") return "hysteria2"
  if (value === "tuic") return "tuic"
  if (value === "trojan") return "trojan"
  if (value === "shadowsocks" || value === "ss") return "shadowsocks"
  if (value === "anytls") return "anytls"
  if (value === "naive" || value === "naiveproxy") return "naive"
  if (value === "wireguard" || value === "wg") return "wireguard"
  if (
    value === "awgwg" ||
    value === "wgawg" ||
    value === "wireguardamneziawg" ||
    value === "amneziawgwireguard"
  ) {
    return "wireguard_ambiguous"
  }
  if (
    value === "amneziawg" ||
    value === "amnezia" ||
    value === "awg" ||
    value.startsWith("amneziawg")
  ) {
    return "amneziawg"
  }
  if (value === "openvpn" || value === "ovpn") return "openvpn"
  if (
    value === "ipsec" ||
    value === "ike" ||
    value === "ikev1" ||
    value === "ikev2"
  ) {
    return "ipsec"
  }
  if (value === "l2tp" || value === "l2tpipsec") return "l2tp"
  if (value === "sstp") return "sstp"
  if (value === "openconnect" || value === "ocserv") return "openconnect"
  if (value.startsWith("socks")) return "socks"
  if (value === "http" || value === "https" || value === "httpproxy") {
    return "http"
  }
  if (value.includes("freeturn")) return "freeturn"
  if (value.includes("wdtt")) return "wdtt"
  return "unknown"
}

const protocolMarks = {
  vless: "VLESS",
  vmess: "VMESS",
  hysteria1: "HYSTERIA",
  hysteria2: "HYSTERIA2",
  tuic: "TUIC",
  trojan: "TROJAN",
  shadowsocks: "SHADOWSOCKS",
  anytls: "ANYTLS",
  naive: "NAIVE",
  wireguard: "WG",
  amneziawg: "AWG",
  wireguard_ambiguous: "AWG/WG",
  openvpn: "OPENVPN",
  ipsec: "IKE/IPSEC",
  l2tp: "L2TP",
  sstp: "SSTP",
  openconnect: "OPENCONNECT",
  socks: "SOCKS5",
  http: "HTTP(S)",
  freeturn: "FREETURN",
  wdtt: "WDTT",
  unknown: "OTHER",
} as const satisfies Readonly<Record<ProtocolVisualKind, string>>

export type ProtocolVisualMark =
  (typeof protocolMarks)[keyof typeof protocolMarks]

export function getProtocolVisualMark(
  protocol: string | null | undefined
): ProtocolVisualMark {
  return protocolMarks[normalizeProtocolVisualKind(protocol)]
}

export function getProtocolVisualMarkForKind(
  kind: ProtocolVisualKind
): ProtocolVisualMark {
  return protocolMarks[kind]
}

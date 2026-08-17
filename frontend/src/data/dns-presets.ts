export const DNS_PRESET_IDS = [
  "yandex",
  "google",
  "cloudflare",
  "quad9",
  "opendns",
] as const

export type DnsPresetId = (typeof DNS_PRESET_IDS)[number]

export type DnsPreset = {
  id: DnsPresetId
  name: string
  primaryAddress: string
  secondaryAddress: string
}

export const DNS_PRESETS: readonly DnsPreset[] = [
  {
    id: "yandex",
    name: "Yandex DNS",
    primaryAddress: "77.88.8.8",
    secondaryAddress: "77.88.8.1",
  },
  {
    id: "google",
    name: "Google Public DNS",
    primaryAddress: "8.8.8.8",
    secondaryAddress: "8.8.4.4",
  },
  {
    id: "cloudflare",
    name: "Cloudflare",
    primaryAddress: "1.1.1.1",
    secondaryAddress: "1.0.0.1",
  },
  {
    id: "quad9",
    name: "Quad9",
    primaryAddress: "9.9.9.9",
    secondaryAddress: "149.112.112.112",
  },
  {
    id: "opendns",
    name: "OpenDNS",
    primaryAddress: "208.67.222.222",
    secondaryAddress: "208.67.220.220",
  },
]

export function getDnsPreset(id: DnsPresetId) {
  return DNS_PRESETS.find((preset) => preset.id === id)
}

export function findDnsPresetByAddress(address?: string) {
  const normalized = address?.trim()
  if (!normalized) {
    return undefined
  }

  return DNS_PRESETS.find(
    (preset) =>
      preset.primaryAddress === normalized ||
      preset.secondaryAddress === normalized
  )
}

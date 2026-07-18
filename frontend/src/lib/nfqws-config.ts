export type NfqwsConfigForm = {
  ISP_INTERFACE: string
  NFQWS_BASE_ARGS: string
  NFQWS_ARGS: string
  NFQWS_ARGS_QUIC: string
  NFQWS_ARGS_UDP: string
  NFQWS_EXTRA_ARGS: "MODE_LIST" | "MODE_ALL" | "MODE_AUTO"
  NFQWS_ARGS_IPSET: string
  NFQWS_ARGS_CUSTOM: string
  IPV6_ENABLED: boolean
  TCP_PORTS: string
  UDP_PORTS: string
  POLICY_NAME: string
  POLICY_EXCLUDE: boolean
  LOG_LEVEL: boolean
}

const keys: (keyof NfqwsConfigForm)[] = [
  "ISP_INTERFACE",
  "NFQWS_BASE_ARGS",
  "NFQWS_ARGS",
  "NFQWS_ARGS_QUIC",
  "NFQWS_ARGS_UDP",
  "NFQWS_EXTRA_ARGS",
  "NFQWS_ARGS_IPSET",
  "NFQWS_ARGS_CUSTOM",
  "IPV6_ENABLED",
  "TCP_PORTS",
  "UDP_PORTS",
  "POLICY_NAME",
  "POLICY_EXCLUDE",
  "LOG_LEVEL",
]

export function parseNfqwsConfig(source: string): NfqwsConfigForm {
  const raw: Record<string, string> = {}
  const lines = source.split("\n")
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index]
    if (!line.trim() || line.trim().startsWith("#")) continue
    const equal = line.indexOf("=")
    if (equal < 1) continue
    const key = line.slice(0, equal).trim()
    let value = line.slice(equal + 1).trim()
    const quote = value[0] === '"' || value[0] === "'" ? value[0] : ""
    if (quote) {
      value = value.slice(1)
      while (!value.includes(quote) && index + 1 < lines.length) {
        index += 1
        value += "\n" + lines[index].trimStart()
      }
      const end = value.lastIndexOf(quote)
      if (end >= 0) value = value.slice(0, end)
    } else {
      value = value.split("#")[0].trim()
    }
    raw[key] = value
  }
  const bool = (name: string) =>
    ["1", "true", "yes"].includes((raw[name] ?? "").toLowerCase())
  const mode = (raw.NFQWS_EXTRA_ARGS ?? "MODE_AUTO").match(
    /MODE_(LIST|ALL|AUTO)/
  )?.[0] as NfqwsConfigForm["NFQWS_EXTRA_ARGS"] | undefined
  return {
    ISP_INTERFACE: raw.ISP_INTERFACE ?? "",
    NFQWS_BASE_ARGS: raw.NFQWS_BASE_ARGS ?? "",
    NFQWS_ARGS: raw.NFQWS_ARGS ?? "",
    NFQWS_ARGS_QUIC: raw.NFQWS_ARGS_QUIC ?? "",
    NFQWS_ARGS_UDP: raw.NFQWS_ARGS_UDP ?? "",
    NFQWS_EXTRA_ARGS: mode ?? "MODE_AUTO",
    NFQWS_ARGS_IPSET: raw.NFQWS_ARGS_IPSET ?? "",
    NFQWS_ARGS_CUSTOM: raw.NFQWS_ARGS_CUSTOM ?? "",
    IPV6_ENABLED: bool("IPV6_ENABLED"),
    TCP_PORTS: raw.TCP_PORTS ?? "",
    UDP_PORTS: raw.UDP_PORTS ?? "",
    POLICY_NAME: raw.POLICY_NAME ?? "",
    POLICY_EXCLUDE: bool("POLICY_EXCLUDE"),
    LOG_LEVEL: bool("LOG_LEVEL"),
  }
}

export function formatNfqwsConfig(
  source: string,
  form: NfqwsConfigForm
): string {
  let result = source
  for (const key of keys) {
    const value = form[key]
    const raw =
      key === "NFQWS_EXTRA_ARGS"
        ? `$${value}`
        : typeof value === "boolean"
          ? value
            ? "1"
            : "0"
          : String(value)
    const rendered =
      raw.includes("\n") || raw.includes(" ") || raw === ""
        ? `"${raw.replaceAll('"', '\\"')}"`
        : raw
    const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
    const pattern = new RegExp(`^${escaped}=.*(?:\\n[ \\t]+.*)*`, "m")
    if (pattern.test(result))
      result = result.replace(pattern, `${key}=${rendered}`)
    else result += `${result.endsWith("\n") ? "" : "\n"}${key}=${rendered}\n`
  }
  return result
}

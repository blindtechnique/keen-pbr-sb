import type { DnsConfig } from "@/api/generated/model/dnsConfig"

/** Missing and null preserve the previously unconditional Firefox signal. */
export function getFirefoxDohCanaryEnabled(
  dns: DnsConfig | undefined
): boolean {
  return dns?.firefox_doh_canary ?? true
}

export function withFirefoxDohCanary(
  dns: DnsConfig | undefined,
  enabled: boolean
): DnsConfig {
  // Unrelated saves keep an existing omitted/null/default representation and
  // all DNS extension fields. Only a changed effective value needs a write.
  return enabled === getFirefoxDohCanaryEnabled(dns)
    ? { ...dns }
    : { ...dns, firefox_doh_canary: enabled }
}

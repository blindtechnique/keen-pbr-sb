import type { ConfigObject } from "@/api/generated/model"
import { isSystemDefaultOutbound } from "@/lib/outbound-display"

export function shouldOfferInitialSetup({
  config,
  isDraft = false,
  loadFailed = false,
  transports,
}: {
  config?: ConfigObject
  isDraft?: boolean
  loadFailed?: boolean
  transports?: readonly unknown[]
}): boolean {
  // Existing settings, drafts and failed requests are not empty installations.
  // No persisted onboarding flag, browser history or extra request is needed.
  return Boolean(
    config &&
    !isDraft &&
    !loadFailed &&
    transports &&
    transports.length === 0 &&
    Object.keys(config.lists ?? {}).length === 0 &&
    (config.route?.rules ?? []).length === 0 &&
    (config.outbounds ?? []).every(isSystemDefaultOutbound)
  )
}

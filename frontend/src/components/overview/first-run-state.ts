import type { ConfigObject } from "@/api/generated/model"
import { isSystemDefaultOutbound } from "@/lib/outbound-display"

// Per loaded panel, not a server configuration flag. Opening or postponing
// the wizard never creates a draft; returning to the dashboard must not loop.
export function createInitialSetupSession() {
  let visited = false
  return {
    markVisited() {
      visited = true
    },
    claimAutomaticOpen(emptyInstallation: boolean, search: string) {
      if (!emptyInstallation || search || visited) return false
      visited = true
      return true
    },
  }
}

export const initialSetupSession = createInitialSetupSession()

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

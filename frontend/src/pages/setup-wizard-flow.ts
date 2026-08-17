import type {
  CatalogSetupIntent,
  CatalogSetupPreviewResponse,
  TransportConfigApplyRequest,
  TransportSpec,
} from "@/api/generated/model"
import { createLinkedTransportApplyRequest } from "@/api/mutations"
import {
  generateTransportIdentity,
  inferTransportProtocol,
} from "@/lib/technical-id"

export interface SetupWizardTransportInput {
  readonly link: string
  readonly displayName: string
  readonly existingInterfaces: readonly string[]
  readonly existingTags: readonly string[]
}

export interface SetupWizardTransportResult {
  readonly displayName: string
  readonly outboundTag: string
  readonly request: TransportConfigApplyRequest
}

export interface SetupWizardTransportDependencies {
  readonly applyTransport: (
    request: TransportConfigApplyRequest
  ) => Promise<unknown>
}

/**
 * Creates the transport and its route through the server-owned composite
 * transaction. The browser never reads, copies or posts the full config, so a
 * concurrent edit cannot be overwritten and a failed operation cannot leave
 * an unlinked transport behind.
 */
export async function createSetupWizardTransport(
  input: SetupWizardTransportInput,
  dependencies: SetupWizardTransportDependencies
): Promise<SetupWizardTransportResult> {
  const identity = generateTransportIdentity({
    existingInterfaces: input.existingInterfaces,
    existingTags: input.existingTags,
    protocol: inferTransportProtocol(input.link, undefined),
  })
  const displayName = input.displayName.trim()
  const transport: TransportSpec = {
    tag: identity.tag,
    interface: identity.interfaceName,
    type: "sing-box",
    link: input.link.trim(),
    display_name: displayName,
    auto_start: true,
  }
  const request = createLinkedTransportApplyRequest(transport)

  await dependencies.applyTransport(request)

  return {
    displayName,
    // The composite API derives the linked outbound from the transport. Its
    // stable tag is therefore the transport tag, not a second browser ID.
    outboundTag: identity.tag,
    request,
  }
}

export class SetupWizardVisibleDraftError extends Error {
  constructor() {
    super("Setup wizard requires the active configuration without a draft")
    this.name = "SetupWizardVisibleDraftError"
  }
}

export interface SetupWizardPreviewDependencies {
  readonly reloadActiveConfig: () => Promise<{
    readonly isDraft: boolean
  }>
  readonly previewCatalog: (
    intent: CatalogSetupIntent
  ) => Promise<CatalogSetupPreviewResponse>
}

/**
 * Catalog preview is compare-and-swap protected and deliberately refuses a
 * visible draft. Always reload the authoritative state immediately before a
 * new preview, including after the atomic transport transaction.
 */
export async function previewSetupWizardCatalog(
  intent: CatalogSetupIntent,
  dependencies: SetupWizardPreviewDependencies
): Promise<CatalogSetupPreviewResponse> {
  const activeConfig = await dependencies.reloadActiveConfig()
  if (activeConfig.isDraft) {
    throw new SetupWizardVisibleDraftError()
  }
  return dependencies.previewCatalog(intent)
}

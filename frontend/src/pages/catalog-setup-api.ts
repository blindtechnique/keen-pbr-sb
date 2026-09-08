import {
  postCatalogSetupApply,
  postCatalogSetupPreview,
} from "@/api/generated/keen-api"
import type {
  CatalogSetupApplyResponse,
  CatalogSetupIntent,
  CatalogSetupPreviewResponse,
} from "@/api/generated/model"

export type {
  CatalogSetupApplyResponse,
  CatalogSetupPreviewResponse as CatalogSetupPreview,
  CatalogSetupWarning,
} from "@/api/generated/model"

export function getCatalogSetupInstallState(
  preview: CatalogSetupPreviewResponse
) {
  const installed = preview.summary.lists.filter(
    (list) => list.already_installed
  )
  const pending = preview.summary.lists.filter(
    (list) => !list.already_installed
  )
  const allInstalled = installed.length > 0 && pending.length === 0
  return {
    installed,
    pending,
    allInstalled,
    // Existing lists can still receive source/inline updates without new
    // route or DNS summaries. Only the authoritative candidate identifies a
    // no-op; the summaries describe what to display, not whether to apply.
    noChanges: preview.base_revision === preview.candidate_revision,
  } as const
}

export async function previewCatalogSetup(
  intent: CatalogSetupIntent
): Promise<CatalogSetupPreviewResponse> {
  const response = await postCatalogSetupPreview({ intent })
  if (response.status !== 200) {
    throw new Error("Unexpected catalogue preview response")
  }
  return response.data
}

export async function applyCatalogSetup({
  intent,
  preview,
  acceptWarnings,
}: {
  readonly intent: CatalogSetupIntent
  readonly preview: CatalogSetupPreviewResponse
  readonly acceptWarnings: boolean
}): Promise<CatalogSetupApplyResponse> {
  const response = await postCatalogSetupApply({
    intent,
    base_revision: preview.base_revision,
    candidate_revision: preview.candidate_revision,
    preview_token: preview.preview_token,
    accept_warnings: acceptWarnings,
  })
  if (response.status !== 200) {
    throw new Error("Unexpected catalogue apply response")
  }
  return response.data
}

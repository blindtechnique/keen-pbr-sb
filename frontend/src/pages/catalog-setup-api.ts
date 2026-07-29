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

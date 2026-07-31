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
  const policyChanges =
    (preview.summary.route_rules?.length ?? 0) > 0 ||
    (preview.summary.dns_rules?.length ?? 0) > 0 ||
    Boolean(preview.summary.route_rule) ||
    Boolean(preview.summary.dns_rule) ||
    Boolean(preview.summary.dns_server?.created) ||
    Boolean(preview.summary.blackhole?.created)
  return {
    installed,
    pending,
    allInstalled,
    noChanges: allInstalled && !policyChanges,
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

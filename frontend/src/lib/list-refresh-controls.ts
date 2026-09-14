import type { ListConfig } from "@/api/generated/model/listConfig"
import type { ListRefreshRequest } from "@/api/generated/model/listRefreshRequest"
import type { ListRefreshResponse } from "@/api/generated/model/listRefreshResponse"
import type { ListRefreshState } from "@/api/generated/model/listRefreshState"
import { configKnownFields } from "@/lib/config-known-fields.generated"
import { pickUnknownConfigProperties } from "@/lib/config-unknown-fields"

export type ListShrinkRejection = NonNullable<
  ListRefreshState["shrink_rejection"]
>
export type ListRefreshAction = "refresh" | "force" | "accept"

export function buildListRefreshRequest(
  name: string,
  action: ListRefreshAction,
  rejection?: ListShrinkRejection
): ListRefreshRequest | undefined {
  if (action === "accept") {
    if (!rejection) return undefined
    return {
      name,
      accept_shrink: {
        previous_sha256: rejection.previous_sha256,
        candidate_sha256: rejection.candidate_sha256,
      },
    }
  }
  return action === "force" ? { name, force_refresh: true } : { name }
}

export function didListRefreshComplete(
  response: { status: number; data: unknown },
  requestedName?: string
): boolean {
  if (response.status !== 200 || !response.data) return false
  const data = response.data as Partial<ListRefreshResponse> & {
    code?: unknown
    error?: unknown
  }
  return (
    data.status === "ok" &&
    !data.code &&
    !data.error &&
    Array.isArray(data.failed_lists) &&
    data.failed_lists.length === 0 &&
    Array.isArray(data.refreshed_lists) &&
    (requestedName === undefined ||
      data.refreshed_lists.includes(requestedName))
  )
}

export type ListShrinkPolicyDraft = {
  shrinkMinPreviousEntries?: string
  shrinkMinRetainedPercent?: string
  // Keep the original fraction when its displayed value was not edited.
  // Multiplying then dividing a double by 100 need not round-trip exactly.
  initialShrinkPolicy?: ListConfig["shrink_policy"]
}

export function listShrinkPolicyToDraft(
  policy?: ListConfig["shrink_policy"]
): ListShrinkPolicyDraft {
  return {
    shrinkMinPreviousEntries:
      policy?.min_previous_entries === undefined
        ? ""
        : String(policy.min_previous_entries),
    shrinkMinRetainedPercent:
      policy?.min_retained_fraction === undefined
        ? ""
        : String(retainedPercentForDisplay(policy.min_retained_fraction)),
    ...(policy ? { initialShrinkPolicy: policy } : {}),
  }
}

export function getListShrinkPolicyFromDraft(
  draft: ListShrinkPolicyDraft
): ListConfig["shrink_policy"] {
  const previous = draft.shrinkMinPreviousEntries?.trim() ?? ""
  const retained = draft.shrinkMinRetainedPercent?.trim() ?? ""
  const policy: NonNullable<ListConfig["shrink_policy"]> =
    pickUnknownConfigProperties(
      draft.initialShrinkPolicy,
      configKnownFields.ListSourceShrinkPolicy
    )
  if (!previous && !retained && !Object.keys(policy).length) return undefined
  if (previous) policy.min_previous_entries = Number(previous)
  if (retained) {
    const original = draft.initialShrinkPolicy?.min_retained_fraction
    policy.min_retained_fraction =
      original !== undefined &&
      Number(retained) === retainedPercentForDisplay(original)
        ? original
        : Number(retained) / 100
  }
  return policy
}

function retainedPercentForDisplay(fraction: number): number {
  return Number((fraction * 100).toPrecision(15))
}

export function getListShrinkPreviousError(
  value: string | undefined,
  t: (key: string) => string
): string | undefined {
  const trimmed = value?.trim() ?? ""
  if (!trimmed) return undefined
  return /^\d+$/.test(trimmed) && Number.isSafeInteger(Number(trimmed))
    ? undefined
    : t("pages.listUpsert.shrinkPolicy.invalidPrevious")
}

export function getListShrinkRetainedError(
  value: string | undefined,
  t: (key: string) => string
): string | undefined {
  const trimmed = value?.trim() ?? ""
  if (!trimmed) return undefined
  const number = Number(trimmed)
  return /^\d+(?:\.\d+)?(?:e[+-]?\d+)?$/i.test(trimmed) &&
    Number.isFinite(number) &&
    number >= 0 &&
    number <= 100
    ? undefined
    : t("pages.listUpsert.shrinkPolicy.invalidRetained")
}

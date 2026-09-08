import type { ListSourcePreviewRequest } from "@/api/generated/model/listSourcePreviewRequest"
import type { ListSourcePreviewResponse } from "@/api/generated/model/listSourcePreviewResponse"
import type { TFunction } from "i18next"
import { getCatalogPresetName, type CatalogPreset } from "@/pages/catalog-model"

export type ListSourcePreviewState =
  | { status: "idle" }
  | { status: "pending" }
  | { status: "failed" }
  | { status: "ready"; result: ListSourcePreviewResponse }

// Each mounted source/route has its own token. Dismissal invalidates even a
// fetch implementation which ignores AbortSignal; old failures are ignored too.
export async function runListSourcePreviewRequest(
  active: { current: symbol | null },
  request: () => Promise<ListSourcePreviewResponse>,
  publish: (state: ListSourcePreviewState) => void
): Promise<void> {
  if (active.current) return
  const token = Symbol("list-source-preview")
  active.current = token
  publish({ status: "pending" })
  try {
    const result = await request()
    if (active.current === token) publish({ status: "ready", result })
  } catch {
    // Transport exceptions can contain credential-bearing URLs. Only a
    // localized, actionable failure is presented, never the exception text.
    if (active.current === token) publish({ status: "failed" })
  } finally {
    if (active.current === token) active.current = null
  }
}

export function listSourcePreviewKey(
  request: ListSourcePreviewRequest
): string {
  return JSON.stringify([
    request.url ?? null,
    request.text ?? null,
    request.format ?? "text",
    request.refresh_detour_mode ?? "inherit",
    request.detour ?? "",
    request.fallback_detours ?? [],
  ])
}

export function listSourcePreviewRequest(
  request: ListSourcePreviewRequest
): ListSourcePreviewRequest {
  const format =
    request.format && request.format !== "text"
      ? { format: request.format }
      : {}
  if (request.text !== undefined) return { text: request.text, ...format }
  if (request.refresh_detour_mode !== "override")
    return { url: request.url, ...format, refresh_detour_mode: "inherit" }
  return {
    url: request.url,
    ...format,
    refresh_detour_mode: "override",
    ...(request.detour ? { detour: request.detour } : {}),
    ...(request.fallback_detours?.length
      ? { fallback_detours: request.fallback_detours }
      : {}),
  }
}

export function listSourcePreviewExcerpt(value: string): string {
  return value.slice(0, 160).replace(/https?:\/\/[^\s]+/gi, (address) => {
    try {
      const url = new URL(address)
      url.username = ""
      url.password = ""
      url.search = ""
      url.hash = ""
      return url.toString()
    } catch {
      return "[…]"
    }
  })
}

export interface CatalogPreviewSource {
  id: string
  name: string
  source: Pick<ListSourcePreviewRequest, "url" | "text">
}

export function catalogSourcePreviewRequest(
  source: CatalogPreviewSource["source"],
  detour: string
): ListSourcePreviewRequest {
  if (source.text !== undefined) return { text: source.text }
  if (!detour) return { url: source.url, refresh_detour_mode: "inherit" }
  return {
    url: source.url,
    refresh_detour_mode: "override",
    detour,
    fallback_detours: [],
  }
}

export function getCatalogPreviewSources(
  presets: readonly CatalogPreset[],
  selected: ReadonlySet<string>,
  language?: string
): CatalogPreviewSource[] {
  const result: CatalogPreviewSource[] = []
  const seen = new Set<string>()
  const byId = new Map(presets.map((preset) => [preset.id, preset]))
  const add = (
    id: string,
    name: string,
    url: string | undefined,
    values: readonly string[]
  ) => {
    const source = url?.trim()
      ? { url: url.trim() }
      : { text: values.join("\n") }
    if (!(source.url || source.text)) return
    const key = JSON.stringify(source)
    if (seen.has(key)) return
    seen.add(key)
    result.push({ id, name, source })
  }
  const url = (preset: CatalogPreset | undefined) =>
    preset?.engines?.singbox?.ruleSets?.[0]?.url?.trim() ||
    preset?.engines?.dns?.subscriptionUrl?.trim()
  for (const preset of presets) {
    if (!selected.has(preset.id)) continue
    add(preset.id, getCatalogPresetName(preset, language), url(preset), [
      ...(preset.engines?.dns?.domains ?? []),
      ...(preset.engines?.dns?.subnets ?? []),
    ])
    for (const companion of preset.routingCompanions ?? []) {
      if (
        companion.kind !== "ip" &&
        companion.include !== "ip_cidrs" &&
        !companion.url
      )
        continue
      const source = companion.sourcePresetId
        ? byId.get(companion.sourcePresetId)
        : undefined
      add(
        companion.id,
        getCatalogPresetName(companion, language),
        companion.url?.trim() || url(source),
        source?.engines?.dns?.subnets ?? []
      )
    }
  }
  return result
}

export function listSourcePreviewErrorMessage(
  code: string,
  t: TFunction
): string {
  switch (code) {
    case "leading_zeros":
      return t("listSourcePreview.errors.ipv4LeadingZeros")
    case "invalid_prefix":
      return t("listSourcePreview.errors.prefix")
    case "invalid_address":
      return t("listSourcePreview.errors.ip")
    case "line_too_long":
      return t("listSourcePreview.errors.lineTooLong")
    case "unsupported_format":
      return t("listContentImport.errors.format")
    case "too_large":
    case "entry_limit":
    case "output_limit":
      return t("listContentImport.errors.limit")
    case "invalid_encoding":
      return t("listContentImport.errors.encoding")
    case "json_syntax":
      return t("listContentImport.errors.jsonSyntax")
    case "json_root_array":
      return t("listContentImport.errors.jsonArray")
    case "json_entry_type":
      return t("listContentImport.errors.jsonEntry")
    case "yaml_payload_required":
      return t("listContentImport.errors.yamlPayload")
    case "yaml_syntax":
      return t("listContentImport.errors.yamlSyntax")
    case "yaml_unsupported":
      return t("listContentImport.errors.yamlUnsupported")
    case "invalid_entry":
      return t("listContentImport.errors.entry")
    default:
      return t("listSourcePreview.errors.entry")
  }
}

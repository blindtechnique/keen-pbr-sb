import type { PlainDnsTemplate } from "@/api/generated/model/plainDnsTemplate"
import type { DnsPresetId } from "@/data/dns-presets"

export type DnsPresetSelection =
  | DnsPresetId
  | `saved:${string}`
  | "custom"

export function getSavedDnsTemplateSelection(
  template: Pick<PlainDnsTemplate, "name">
): `saved:${string}` {
  return `saved:${encodeURIComponent(normalizeTemplateName(template.name))}`
}

export function findSavedDnsTemplate(
  selection: DnsPresetSelection,
  templates: readonly PlainDnsTemplate[]
): PlainDnsTemplate | undefined {
  if (!selection.startsWith("saved:")) {
    return undefined
  }
  const encodedName = selection.slice("saved:".length)
  let selectedName: string
  try {
    selectedName = decodeURIComponent(encodedName)
  } catch {
    return undefined
  }
  return templates.find(
    (template) => normalizeTemplateName(template.name) === selectedName
  )
}

function normalizeTemplateName(name: string): string {
  return name.trim().toLocaleLowerCase("en-US")
}

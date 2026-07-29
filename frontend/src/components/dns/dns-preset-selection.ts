import type { PlainDnsTemplate } from "@/api/generated/model/plainDnsTemplate"
import { getDnsPreset, type DnsPresetId } from "@/data/dns-presets"

export type DnsPresetSelection = DnsPresetId | `saved:${string}` | "custom"

export type ResolvedDnsTemplate = {
  name: string
  primaryAddress: string
  secondaryAddress?: string
  technicalSeed: string
}

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

export function resolveDnsTemplateSelection(
  selection: DnsPresetSelection,
  savedTemplates: readonly PlainDnsTemplate[]
): ResolvedDnsTemplate | undefined {
  if (selection === "custom") {
    return undefined
  }
  if (selection.startsWith("saved:")) {
    const template = findSavedDnsTemplate(selection, savedTemplates)
    if (!template) {
      return undefined
    }
    return {
      name: template.name,
      primaryAddress: template.primary_ipv4,
      secondaryAddress: template.secondary_ipv4,
      technicalSeed: template.name,
    }
  }

  const preset = getDnsPreset(selection as DnsPresetId)
  return preset
    ? {
        name: preset.name,
        primaryAddress: preset.primaryAddress,
        secondaryAddress: preset.secondaryAddress,
        technicalSeed: preset.id,
      }
    : undefined
}

function normalizeTemplateName(name: string): string {
  return name.trim().toLocaleLowerCase("en-US")
}

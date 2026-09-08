import {
  localizeCatalogText,
  type CatalogTextTranslations,
} from "@/lib/catalog-localization"

export type ListTemplate = {
  id: string
  name: string
  name_i18n?: CatalogTextTranslations
  description: string
  description_i18n?: CatalogTextTranslations
  url: string
  category: string
  catalogPresetId?: string
}

export function getListTemplateName(
  template: ListTemplate,
  language?: string
): string {
  return localizeCatalogText(template.name, template.name_i18n, language)
}

export function getListTemplateDescription(
  template: ListTemplate,
  language?: string
): string {
  return localizeCatalogText(
    template.description,
    template.description_i18n,
    language
  )
}

export function matchesListTemplateSearch(
  template: ListTemplate,
  query: string,
  language?: string
): boolean {
  const needle = query.trim().toLowerCase()
  return (
    !needle ||
    [
      template.name,
      getListTemplateName(template, language),
      template.description,
      getListTemplateDescription(template, language),
      template.url,
    ].some((value) => value.toLowerCase().includes(needle))
  )
}

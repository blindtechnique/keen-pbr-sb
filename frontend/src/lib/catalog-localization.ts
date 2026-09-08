export type CatalogTextTranslations = Readonly<Record<string, string>>

/** Optional catalogue translations leave older and custom sources readable. */
export function localizeCatalogText(
  original: string | undefined,
  translations: CatalogTextTranslations | undefined,
  language: string | undefined
): string {
  const locale = (language ?? "en").toLowerCase()
  for (const key of new Set([locale, locale.split("-")[0]])) {
    const translated = translations?.[key]
    if (typeof translated === "string" && translated.trim()) {
      return translated
    }
  }
  return original ?? ""
}

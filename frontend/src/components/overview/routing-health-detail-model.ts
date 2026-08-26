type Translate = (key: string) => string

/**
 * Keep backend diagnostic details intact unless they belong to the small,
 * stable vocabulary that the dashboard knows how to present to users.
 */
export function localizeRoutingHealthDetail(
  detail: string | null | undefined,
  t: Translate
) {
  const normalized = detail?.trim().toLocaleLowerCase("en-US")

  if (!normalized || normalized === "ok") {
    return null
  }

  if (normalized === "disabled by configuration") {
    return t("overview.routing.details.disabledByConfiguration")
  }

  return detail
}

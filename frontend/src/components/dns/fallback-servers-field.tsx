import { useTranslation } from "react-i18next"

import type { ConfigObject } from "@/api/generated/model"
import { MultiSelectList } from "@/components/shared/multi-select-list"
import {
  Field,
  FieldContent,
  FieldHint,
  FieldLabel,
} from "@/components/shared/field"

/**
 * Ordered list of DNS servers dnsmasq falls back to when no rule matches.
 * Lives next to the server definitions themselves so both are edited in one
 * place.
 */
export function FallbackServersField({
  config,
  onChange,
}: {
  config: ConfigObject | undefined
  onChange: (fallback: string[]) => void
}) {
  const { t } = useTranslation()
  const serverTags = (config?.dns?.servers ?? [])
    .map((server) => server.tag)
    .filter((tag): tag is string => Boolean(tag))

  return (
    <Field>
      <FieldLabel>{t("pages.dnsRules.fallback.title")}</FieldLabel>
      <FieldContent>
        <MultiSelectList
          addLabel={t("pages.dnsRules.fallback.add")}
          allowReorder
          emptyMessage={t("pages.dnsRules.fallback.noneAvailable")}
          onChange={onChange}
          options={serverTags}
          placeholderDescription={t(
            "pages.dnsRules.fallback.placeholderDescription"
          )}
          placeholderTitle={t("pages.dnsRules.fallback.placeholderTitle")}
          value={config?.dns?.fallback ?? []}
        />
        <FieldHint
          description={
            serverTags.length === 0 ? (
              <>
                {t("pages.dnsRules.fallback.description")}{" "}
                {t("pages.dnsRules.fallback.noneDefined")}
              </>
            ) : (
              t("pages.dnsRules.fallback.description")
            )
          }
        />
      </FieldContent>
    </Field>
  )
}

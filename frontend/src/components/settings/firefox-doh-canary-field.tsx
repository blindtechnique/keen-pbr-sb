import type { ReactNode } from "react"
import { useTranslation } from "react-i18next"

import {
  Field,
  FieldContent,
  FieldHint,
  FieldLabel,
} from "@/components/shared/field"
import { Checkbox } from "@/components/ui/checkbox"

export function FirefoxDohCanaryField({
  value,
  onChange,
  error,
  className,
}: {
  value: boolean
  onChange: (value: boolean) => void
  error?: ReactNode
  className?: string
}) {
  const { t } = useTranslation()
  return (
    <Field width="short" className={className}>
      <FieldContent>
        <div className="flex items-center space-x-3">
          <Checkbox
            checked={value}
            id="firefox-doh-canary"
            aria-describedby="firefox-doh-canary-hint"
            aria-invalid={Boolean(error)}
            onCheckedChange={(checked) => onChange(checked === true)}
          />
          <FieldLabel
            className="cursor-pointer flex-col items-start gap-0"
            htmlFor="firefox-doh-canary"
          >
            {t("pages.settings.general.firefoxDohCanaryLabel")}
          </FieldLabel>
        </div>
        <div id="firefox-doh-canary-hint">
          <FieldHint
            description={t("pages.settings.general.firefoxDohCanaryHint")}
            error={error}
          />
        </div>
        <details className="mt-1 text-xs text-muted-foreground">
          <summary className="cursor-pointer">
            {t("pages.settings.general.firefoxDohCanaryScopeLabel")}
          </summary>
          <p className="mt-1">
            {t("pages.settings.general.firefoxDohCanaryScope")}
          </p>
        </details>
      </FieldContent>
    </Field>
  )
}

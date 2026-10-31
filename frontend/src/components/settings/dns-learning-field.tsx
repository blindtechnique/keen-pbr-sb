import { useTranslation } from "react-i18next"
import type { ReactNode } from "react"
import { Checkbox } from "@/components/ui/checkbox"
import { Field, FieldLabel, FieldHint } from "@/components/shared/field"

export function DnsLearningField({
  kind,
  value,
  onChange,
  error,
}: {
  kind: "dns" | "l7"
  value: boolean
  onChange: (enabled: boolean) => void
  error?: ReactNode
}) {
  const { t } = useTranslation()
  const id = `dns-learning-${kind}`
  return (
    <Field invalid={Boolean(error)} width="short">
      <div className="flex items-center gap-3">
        <Checkbox
          id={id}
          checked={value}
          onCheckedChange={(checked) => onChange(checked === true)}
          aria-describedby={`${id}-hint`}
          aria-invalid={Boolean(error)}
        />
        <FieldLabel htmlFor={id} className="cursor-pointer">
          {kind === "dns" ? t("learning.dnsLabel") : t("learning.l7Label")}
        </FieldLabel>
      </div>
      <p id={`${id}-hint`} className="text-sm text-muted-foreground">
        {kind === "dns" ? t("learning.dnsHint") : t("learning.l7Hint")}
      </p>
      <FieldHint error={error} />
    </Field>
  )
}

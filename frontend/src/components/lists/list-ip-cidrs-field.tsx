import { useTranslation } from "react-i18next"

import { CodeEditor } from "@/components/shared/code-editor"
import type { CodeEditorSelection } from "@/components/shared/code-editor-selection"
import {
  Field,
  FieldContent,
  FieldHint,
  FieldLabel,
} from "@/components/shared/field"
import { getFirstFieldError } from "@/lib/form-field-error"

export function ListIpCidrsField({
  value,
  onChange,
  onBlur,
  errors,
  selection,
}: {
  value: string
  onChange: (value: string) => void
  onBlur: () => void
  errors: unknown[]
  selection?: CodeEditorSelection | null
}) {
  const { t } = useTranslation()
  const error = getFirstFieldError(errors)
  return (
    <Field data-invalid={Boolean(error)}>
      <FieldLabel htmlFor="list-ip-cidrs">
        {t("pages.listUpsert.fields.ipCidrs")}
      </FieldLabel>
      <FieldContent>
        <CodeEditor
          aria-describedby="list-ip-cidrs-hint"
          aria-invalid={Boolean(error)}
          className="min-h-24"
          id="list-ip-cidrs"
          onBlur={onBlur}
          onChange={onChange}
          selection={selection}
          syntax="list"
          value={value}
        />
        <div id="list-ip-cidrs-hint">
          <FieldHint
            description={t("pages.listUpsert.fields.ipCidrsHint")}
            error={error}
          />
        </div>
      </FieldContent>
    </Field>
  )
}

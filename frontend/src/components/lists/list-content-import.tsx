import { useEffect, useId, useRef, useState, type ReactNode } from "react"
import { useTranslation } from "react-i18next"
import { postListContentImport } from "@/api/generated/keen-api"
import type { ListContentImportResponse } from "@/api/generated/model/listContentImportResponse"
import { Button } from "@/components/ui/button"
import { Textarea } from "@/components/ui/textarea"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  Field,
  FieldContent,
  FieldHint,
  FieldLabel,
} from "@/components/shared/field"
import {
  listContentTextTooLarge,
  readListContentFile,
  runListContentImport,
  type ListContentFormat,
  type ListContentImportState,
  type ListImportAdded,
} from "./list-content-import-model"
import {
  listSourcePreviewErrorMessage,
  listSourcePreviewExcerpt,
} from "./list-source-preview-model"

export function ListSourceFormatField({
  value,
  onChange,
  source = false,
  error,
}: {
  value: ListContentFormat
  onChange: (value: ListContentFormat) => void
  source?: boolean
  error?: ReactNode
}) {
  const { t } = useTranslation()
  const id = useId()
  const items = [
    { value: "text", label: t("listContentImport.formats.text") },
    { value: "json-array", label: t("listContentImport.formats.jsonArray") },
    {
      value: "yaml-payload",
      label: t("listContentImport.formats.yamlPayload"),
    },
  ]
  return (
    <Field data-invalid={Boolean(error)}>
      <FieldLabel htmlFor={id}>{t("listContentImport.format")}</FieldLabel>
      <FieldContent>
        <Select
          items={items}
          value={value}
          onValueChange={(next) => {
            if (
              next === "text" ||
              next === "json-array" ||
              next === "yaml-payload"
            )
              onChange(next)
          }}
        >
          <SelectTrigger id={id} aria-invalid={Boolean(error)}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {items.map((item) => (
              <SelectItem key={item.value} value={item.value}>
                {item.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {source ? (
          <>
            <FieldHint
              description={t("listContentImport.sourceFormatHint")}
              error={error}
            />
            <FieldHint
              description={
                value === "json-array"
                  ? t("listContentImport.jsonHint")
                  : value === "yaml-payload"
                    ? t("listContentImport.yamlHint")
                    : t("listContentImport.textHint")
              }
            />
          </>
        ) : null}
      </FieldContent>
    </Field>
  )
}

export function ListContentImport({
  onAdd,
}: {
  onAdd: (result: ListContentImportResponse) => ListImportAdded
}) {
  const { t } = useTranslation()
  const id = useId()
  const [format, setFormat] = useState<ListContentFormat>("text")
  const [text, setText] = useState("")
  const [state, setState] = useState<ListContentImportState>({ status: "idle" })
  const session = useRef<symbol | null>(null)
  const input = useRef<HTMLInputElement>(null)
  useEffect(
    () => () => {
      session.current = null
    },
    []
  )
  const invalidate = () => {
    session.current = null
    setState({ status: "idle" })
  }
  const hint =
    format === "json-array"
      ? t("listContentImport.jsonHint")
      : format === "yaml-payload"
        ? t("listContentImport.yamlHint")
        : t("listContentImport.textHint")
  const example =
    format === "json-array"
      ? '["example.org", "192.0.2.0/24"]'
      : format === "yaml-payload"
        ? "payload:\n  - example.org\n  - 192.0.2.0/24"
        : "example.org\n192.0.2.0/24"
  const pending = state.status === "pending" || state.status === "reading"
  return (
    <details
      className="rounded-md border border-border p-3"
      onToggle={(event) => {
        if (!event.currentTarget.open) invalidate()
      }}
    >
      <summary className="cursor-pointer text-sm font-medium">
        {t("listContentImport.title")}
      </summary>
      <div className="mt-4 space-y-4">
        <p className="text-sm text-muted-foreground">
          {t("listContentImport.hint")}
        </p>
        <ListSourceFormatField
          value={format}
          onChange={(next) => {
            invalidate()
            setFormat(next)
          }}
        />
        <Field>
          <FieldLabel htmlFor={id}>
            {t("listContentImport.contents")}
          </FieldLabel>
          <FieldContent>
            <Textarea
              id={id}
              aria-describedby={id + "-hint"}
              className="max-h-64 min-h-32 overflow-y-auto font-mono text-xs"
              value={text}
              placeholder={example}
              spellCheck={false}
              onChange={(event) => {
                invalidate()
                setText(event.target.value)
              }}
            />
            <div id={id + "-hint"}>
              <FieldHint description={hint} />
            </div>
          </FieldContent>
        </Field>
        <div className="flex flex-wrap gap-2">
          <Button
            type="button"
            variant="outline"
            onClick={() => input.current?.click()}
          >
            {t("listContentImport.chooseFile")}
          </Button>
          <input
            ref={input}
            type="file"
            className="hidden"
            accept=".txt,.json,.yaml,.yml,text/plain,application/json,application/yaml,text/yaml"
            onChange={(event) => {
              const file = event.target.files?.[0]
              event.target.value = ""
              if (file)
                void readListContentFile(session, file, setText, setState)
            }}
          />
          <Button
            type="button"
            disabled={!text.trim() || pending}
            onClick={() => {
              if (listContentTextTooLarge(text)) {
                setState({ status: "failed", reason: "tooLarge" })
                return
              }
              void runListContentImport(
                session,
                async () => {
                  const response = await postListContentImport({ text, format })
                  if (response.status !== 200) return Promise.reject()
                  return response.data
                },
                onAdd,
                setState
              )
            }}
          >
            {t("listContentImport.add")}
          </Button>
        </div>
        <div role="status" aria-live="polite" className="space-y-2 text-sm">
          {state.status === "reading" ? t("listContentImport.reading") : null}
          {state.status === "pending" ? t("listContentImport.checking") : null}
          {state.status === "failed" ? (
            <p>
              {state.reason === "tooLarge"
                ? t("listContentImport.tooLarge")
                : state.reason === "readFailed"
                  ? t("listContentImport.readFailed")
                  : t("listContentImport.requestFailed")}
            </p>
          ) : null}
          {state.status === "added" ? (
            <p>{t("listContentImport.added", state.added)}</p>
          ) : null}
          {state.status === "invalid" ? (
            <>
              <p>
                {state.result.limit_reason
                  ? t("listContentImport.incomplete")
                  : t("listContentImport.invalid")}
              </p>
              <ul className="space-y-1">
                {state.result.errors.slice(0, 10).map((error, index) => (
                  <li key={index}>
                    {t("listSourcePreview.errorLine", {
                      line: error.line,
                      message: listSourcePreviewErrorMessage(error.code, t),
                    })}
                    {error.value ? (
                      <code className="ml-1 break-all">
                        {listSourcePreviewExcerpt(error.value)}
                      </code>
                    ) : null}
                  </li>
                ))}
              </ul>
              {state.result.errors_limited ||
              state.result.errors.length > 10 ? (
                <p className="text-xs text-muted-foreground">
                  {t("listContentImport.errorsLimited")}
                </p>
              ) : null}
            </>
          ) : null}
        </div>
      </div>
    </details>
  )
}

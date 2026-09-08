import { useEffect, useRef, useState } from "react"
import { useTranslation } from "react-i18next"
import { postListSourcePreview } from "@/api/generated/keen-api"
import type { ListSourcePreviewRequest } from "@/api/generated/model/listSourcePreviewRequest"
import type { ListSourcePreviewResponse } from "@/api/generated/model/listSourcePreviewResponse"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import type { CatalogPreset } from "@/pages/catalog-model"
import {
  catalogSourcePreviewRequest,
  getCatalogPreviewSources,
  listSourcePreviewErrorMessage,
  listSourcePreviewExcerpt,
  listSourcePreviewKey,
  listSourcePreviewRequest,
  runListSourcePreviewRequest,
  type ListSourcePreviewState,
} from "./list-source-preview-model"

export function ListSourcePreview({
  request,
  title,
}: {
  request: ListSourcePreviewRequest
  title?: string
}) {
  // Changing any source/route field unmounts the old session immediately,
  // clearing its result and invalidating late responses without dirtying forms.
  return (
    <PreviewSession
      key={listSourcePreviewKey(request)}
      request={listSourcePreviewRequest(request)}
      title={title}
    />
  )
}

function PreviewSession({
  request,
  title,
}: {
  request: ListSourcePreviewRequest
  title?: string
}) {
  const { t } = useTranslation()
  const [state, setState] = useState<ListSourcePreviewState>({ status: "idle" })
  const active = useRef<symbol | null>(null)
  const button = useRef<HTMLButtonElement>(null)
  const result = useRef<HTMLDivElement>(null)
  useEffect(
    () => () => {
      active.current = null
    },
    []
  )
  useEffect(() => {
    if (
      (state.status === "ready" || state.status === "failed") &&
      document.activeElement === button.current
    ) {
      result.current?.focus({ preventScroll: true })
    }
  }, [state])
  return (
    <section
      aria-label={title ?? t("listSourcePreview.title")}
      className="space-y-3 rounded-md border border-border p-3"
    >
      {title ? <h4 className="text-sm font-medium">{title}</h4> : null}
      <div className="flex flex-wrap items-center gap-3">
        <Button
          ref={button}
          type="button"
          size="sm"
          variant="outline"
          disabled={!(request.url?.trim() || request.text?.trim())}
          aria-disabled={state.status === "pending"}
          aria-busy={state.status === "pending"}
          onClick={() =>
            void runListSourcePreviewRequest(
              active,
              async () => {
                const response = await postListSourcePreview(request)
                if (response.status !== 200) return Promise.reject()
                return response.data
              },
              setState
            )
          }
        >
          {t("listSourcePreview.button")}
        </Button>
        <p className="text-xs text-muted-foreground">
          {t("listSourcePreview.hint")}
        </p>
      </div>
      {state.status === "pending" ? (
        <div role="status" aria-live="polite" className="space-y-2">
          <p className="text-sm text-muted-foreground">
            {t(
              request.url
                ? "listSourcePreview.loadingRemote"
                : "listSourcePreview.loadingInline"
            )}
          </p>
          <Skeleton className="h-5 w-4/5" />
          <Skeleton className="h-5 w-3/5" />
        </div>
      ) : null}
      {state.status === "failed" || state.status === "ready" ? (
        <div
          ref={result}
          tabIndex={-1}
          role="status"
          aria-live="polite"
          className="rounded-sm focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
        >
          {state.status === "failed" ? (
            <p className="text-sm">{t("listSourcePreview.failed")}</p>
          ) : (
            <ListSourcePreviewResult result={state.result} />
          )}
        </div>
      ) : null}
    </section>
  )
}

export function ListSourcePreviewResult({
  result,
}: {
  result: ListSourcePreviewResponse
}) {
  const { t } = useTranslation()
  const failure =
    result.status === "download_failed"
      ? t("listSourcePreview.downloadFailed")
      : result.status === "too_large"
        ? t("listSourcePreview.tooLarge")
        : result.status === "unsupported_format"
          ? t("listSourcePreview.unsupportedFormat")
          : result.status === "route_unavailable"
            ? t("listSourcePreview.routeUnavailable")
            : null
  if (failure) return <p className="text-sm">{failure}</p>
  const counts = [
    [t("listSourcePreview.counts.lines"), result.lines],
    [t("listSourcePreview.counts.valid"), result.valid_entries],
    [t("listSourcePreview.counts.unique"), result.unique_entries],
    [t("listSourcePreview.counts.duplicates"), result.duplicates],
    [t("listSourcePreview.counts.invalid"), result.invalid_entries],
    [t("listSourcePreview.counts.ignored"), result.ignored_lines],
    [t("listSourcePreview.counts.ipv4"), result.ipv4],
    [t("listSourcePreview.counts.ipv6"), result.ipv6],
    [t("listSourcePreview.counts.domains"), result.domains],
  ] as const
  return (
    <div className="space-y-3">
      {!result.complete ? (
        <p className="text-sm text-muted-foreground">
          {t(
            result.limit_reason === "line_too_long"
              ? "listSourcePreview.lineTooLongStop"
              : "listSourcePreview.partial"
          )}
        </p>
      ) : null}
      <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm sm:grid-cols-3">
        {counts.map(([label, value]) => (
          <div key={label}>
            <dt className="text-xs text-muted-foreground">{label}</dt>
            <dd className="font-medium tabular-nums">{value}</dd>
          </div>
        ))}
      </dl>
      {result.entries.length > 0 ? (
        <details className="rounded-md border border-border p-2">
          <summary className="cursor-pointer text-sm font-medium">
            {t("listSourcePreview.entries", {
              count: Math.min(result.entries.length, 50),
            })}
          </summary>
          <ol className="mt-2 max-h-64 space-y-1 overflow-y-auto text-xs">
            {result.entries.slice(0, 50).map((entry) => (
              <li key={`${entry.line}:${entry.value}`} className="flex gap-2">
                <span className="shrink-0 text-muted-foreground">
                  {t("listSourcePreview.line", { line: entry.line })}
                </span>
                <code className="min-w-0 break-all">{entry.value}</code>
              </li>
            ))}
          </ol>
          {result.entries_limited ? (
            <p className="mt-2 text-xs text-muted-foreground">
              {t("listSourcePreview.entriesLimited")}
            </p>
          ) : null}
        </details>
      ) : (
        <p className="text-sm text-muted-foreground">
          {t("listSourcePreview.empty")}
        </p>
      )}
      {result.errors.length > 0 ? (
        <details className="rounded-md border border-border p-2">
          <summary className="cursor-pointer text-sm font-medium">
            {t("listSourcePreview.errorsTitle", {
              count: result.invalid_entries,
            })}
          </summary>
          <ul className="mt-2 max-h-64 space-y-2 overflow-y-auto text-xs">
            {result.errors.slice(0, 50).map((error, index) => (
              <li key={`${error.line}:${index}`}>
                {t("listSourcePreview.errorLine", {
                  line: error.line,
                  message: listSourcePreviewErrorMessage(error.code, t),
                })}
                {error.value ? (
                  <code className="mt-1 block rounded bg-muted px-2 py-1 break-all">
                    {listSourcePreviewExcerpt(error.value)}
                  </code>
                ) : null}
              </li>
            ))}
          </ul>
          {result.errors_limited ? (
            <p className="mt-2 text-xs text-muted-foreground">
              {t("listSourcePreview.errorsLimited")}
            </p>
          ) : null}
        </details>
      ) : null}
    </div>
  )
}

export function CatalogSourcePreviews({
  presets,
  selected,
  detour,
}: {
  presets: readonly CatalogPreset[]
  selected: ReadonlySet<string>
  detour: string
}) {
  const { t, i18n } = useTranslation()
  const [open, setOpen] = useState(false)
  const sources = getCatalogPreviewSources(presets, selected, i18n.language)
  if (sources.length === 0) return null
  return (
    <details
      className="rounded-md border border-border p-3"
      open={open}
      onToggle={(event) => setOpen(event.currentTarget.open)}
    >
      <summary className="cursor-pointer text-sm font-medium">
        {t("listSourcePreview.catalogTitle")}
      </summary>
      {open ? (
        <div className="mt-3 space-y-3">
          {sources.map((source) => (
            <ListSourcePreview
              key={source.id}
              title={source.name}
              request={catalogSourcePreviewRequest(source.source, detour)}
            />
          ))}
        </div>
      ) : null}
    </details>
  )
}

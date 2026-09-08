import {
  CheckCircle2Icon,
  InfoIcon,
  LoaderCircleIcon,
  XCircleIcon,
} from "lucide-react"
import { useEffect, useRef, useState } from "react"

import type { ApiError } from "@/api/client"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"

import type {
  SubscriptionApplyResponse,
  SubscriptionPreviewCandidate,
  SubscriptionPreviewResponse,
  SubscriptionPreviewRequest,
} from "@/api/generated/model"
import {
  usePostSubscriptionApplyMutation,
  usePostSubscriptionPreviewMutation,
} from "@/api/mutations"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { OperationErrorMessage } from "@/components/shared/operation-error-message"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { cn } from "@/lib/utils"

import {
  buildSelections,
  getSubscriptionPreviewRefusalReason,
  initialSelectedLines,
  initialNewServerLines,
  isSelectable,
  MAXIMUM_SUBSCRIPTION_SELECTION,
  requiresTagOverride,
  selectionProblems,
  toggleSelectedLine,
} from "./subscription-import-model"
import { runSubscriptionPreviewRequest } from "./subscription-preview-request"

// The dialog walks one direction: url -> preview -> results. The preview
// holds no share links - the backend keeps those in daemon memory behind the
// preview id - so everything shown here is safe to render, log, or screenshot.
export function SubscriptionImportDialog({
  onComplete,
  onOpenChange,
  onResultsDismiss,
  open,
  seed,
}: {
  onComplete: (results: SubscriptionApplyResponse) => void
  onOpenChange: (open: boolean) => void
  onResultsDismiss: () => void
  open: boolean
  // What the add-transport modal already has in hand. The operator pasted a
  // subscription URL or chose a subscription file there; asking them for it a
  // second time in this dialog would be the modal admitting it did not
  // understand what they gave it.
  seed?:
    | { readonly url: string }
    | { readonly document: string }
    | { readonly subscription_id: string; readonly pending_only: true }
}) {
  const { t } = useTranslation()
  const [url, setUrl] = useState("")
  const [subscriptionName, setSubscriptionName] = useState("")
  const [preview, setPreview] = useState<SubscriptionPreviewResponse | null>(
    null
  )
  const [results, setResults] = useState<SubscriptionApplyResponse | null>(null)
  const [selected, setSelected] = useState<Set<number>>(new Set())
  const [overrides, setOverrides] = useState<Map<number, string>>(new Map())
  const focusedProblemRef = useRef<string | null>(null)
  const previewRequest = useRef<symbol | null>(null)
  const newServersOnly = Boolean(
    seed && "subscription_id" in seed && seed.pending_only
  )

  const previewMutation = usePostSubscriptionPreviewMutation()
  const applyMutation = usePostSubscriptionApplyMutation()

  useEffect(
    () => () => {
      previewRequest.current = null
    },
    []
  )

  const resetPreview = () => {
    previewRequest.current = null
    previewMutation.reset()
  }

  const reset = () => {
    resetPreview()
    setUrl("")
    setSubscriptionName("")
    setPreview(null)
    setResults(null)
    setSelected(new Set())
    setOverrides(new Map())
    applyMutation.reset()
  }

  const close = (next: boolean) => {
    if (!next) {
      // Closing mid-apply would not abort anything: the daemon keeps creating
      // the selected transports and the per-entry outcomes would never be
      // seen. The dialog stays open until the answer arrives.
      if (applyMutation.isPending) return
      // Escape and a backdrop click land here too, and during selection they
      // would silently discard every checkbox and tag edit.
      // Once a mixed result has been shown, however, some durable work may
      // already have left this form. Any deliberate exit must finish the
      // source dialog too instead of returning to its stale URL and showing a
      // false unsaved-changes warning.
      if (results) {
        reset()
        onOpenChange(false)
        onResultsDismiss()
        return
      }
      if (
        preview &&
        (selected.size > 0 || overrides.size > 0) &&
        !window.confirm(t("transports.subscriptionImport.discardConfirm"))
      ) {
        return
      }
      reset()
    }
    onOpenChange(next)
  }

  const fetchPreview = (source?: SubscriptionPreviewRequest) => {
    void runSubscriptionPreviewRequest(
      previewRequest,
      () =>
        previewMutation.mutateAsync({ data: source ?? { url: url.trim() } }),
      (response) => {
        if (response.status === 200) {
          setPreview(response.data)
          setSubscriptionName(
            (current) => current || response.data.subscription_name || ""
          )
          setSelected(
            newServersOnly
              ? initialNewServerLines(response.data.candidates)
              : initialSelectedLines(response.data.candidates)
          )
          setOverrides(new Map())
        }
      }
    )
  }

  // Seeded openings skip the URL step. Keyed on `open` so closing and
  // reopening with a different subscription starts over rather than showing
  // the previous one, and guarded on the mutation so a re-render cannot fetch
  // the same subscription twice.
  useEffect(() => {
    if (!open || !seed) return
    if (preview || previewMutation.isPending) return
    if ("url" in seed) setUrl(seed.url)
    fetchPreview(seed)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, seed])

  const problems = preview
    ? selectionProblems(preview.candidates, selected, overrides)
    : []
  const firstProblem = problems[0]

  useEffect(() => {
    if (!preview || results || !firstProblem) {
      focusedProblemRef.current = null
      return
    }
    const problemKey = `${preview.preview_id}:${firstProblem.line}:${firstProblem.kind}`
    if (focusedProblemRef.current === problemKey) return
    focusedProblemRef.current = problemKey
    queueMicrotask(() => {
      const input = document.getElementById(
        `subscription-tag-${firstProblem.line}`
      )
      input?.scrollIntoView({ behavior: "smooth", block: "center" })
      input?.focus()
    })
  }, [firstProblem, preview, results])

  const apply = () => {
    if (!preview || problems.length > 0) return
    const selections = buildSelections(preview.candidates, selected, overrides)
    if (selections.length === 0) return
    applyMutation.mutate(
      {
        data: {
          preview_id: preview.preview_id,
          selections,
          subscription_name:
            subscriptionName.trim() === preview.subscription_name
              ? undefined
              : subscriptionName.trim() || undefined,
        },
      },
      {
        onSuccess: (response) => {
          if (response.status === 200) {
            setResults(response.data)
            if (response.data.subscription_error)
              toast.warning(t("subscriptions.importMetadataFailed"))
            // A partial result must stay visible: otherwise the operator
            // cannot tell which entries need attention. A complete success
            // has no remaining form state, so close both nested and source
            // dialogs without offering the http URL as a second transport.
            if (
              response.data.results.length > 0 &&
              response.data.results.every(
                (result) => result.outcome !== "failed"
              )
            ) {
              onComplete(response.data)
            }
          }
        },
      }
    )
  }

  const toggle = (line: number) => {
    setSelected((current) => toggleSelectedLine(current, line))
  }

  const setOverride = (line: number, value: string) => {
    setOverrides((current) => {
      const next = new Map(current)
      if (value) {
        next.set(line, value)
      } else {
        next.delete(line)
      }
      return next
    })
  }

  const hasCandidates = (preview?.candidates.length ?? 0) > 0
  const selectionCount = preview
    ? buildSelections(preview.candidates, selected, overrides).length
    : 0
  // The daemon erases a preview after ten minutes (or a restart) and answers
  // apply with 410. Retrying the same preview_id can only 410 again, so the
  // dead end needs its own exit: back to the URL step with the URL kept.
  const previewExpired =
    (applyMutation.error as ApiError | null)?.status === 410
  const refetchExpired = () => {
    setPreview(null)
    setResults(null)
    setSelected(new Set())
    setOverrides(new Map())
    applyMutation.reset()
    resetPreview()
    if (seed) fetchPreview(seed)
  }
  // The preview refusal carries a machine-readable reason; showing the
  // operator which rule refused their URL beats a generic sentence.
  const previewError = previewMutation.error as ApiError | null
  const previewReason = getSubscriptionPreviewRefusalReason(previewError)

  return (
    <Dialog onOpenChange={close} open={open}>
      <DialogContent className="max-sm:top-auto max-sm:bottom-0 max-sm:left-0 max-sm:max-h-[calc(100dvh-0.75rem)] max-sm:max-w-none max-sm:translate-x-0 max-sm:translate-y-0 max-sm:overflow-y-auto max-sm:rounded-b-none max-sm:border-x-0 max-sm:border-b-0 sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>
            {newServersOnly
              ? t("subscriptions.previewNewServers")
              : t("transports.subscriptionImport.title")}
          </DialogTitle>
          <DialogDescription>
            {newServersOnly
              ? t("subscriptions.newServersHint")
              : t("transports.subscriptionImport.description")}
          </DialogDescription>
        </DialogHeader>

        {results ? (
          <ResultsView results={results} />
        ) : preview ? (
          <div className="space-y-3">
            {hasCandidates ? (
              <>
                {url ? (
                  <label className="block space-y-1 text-sm">
                    <span>{t("subscriptions.optionalName")}</span>
                    <Input
                      maxLength={80}
                      value={subscriptionName}
                      onChange={(event) =>
                        setSubscriptionName(event.target.value)
                      }
                      disabled={applyMutation.isPending}
                    />
                  </label>
                ) : null}
                <p className="text-xs text-muted-foreground">
                  {t("transports.subscriptionImport.selectionLimit", {
                    count: selectionCount,
                    limit: MAXIMUM_SUBSCRIPTION_SELECTION,
                  })}
                </p>
                <div className="max-h-[50vh] space-y-2 overflow-y-auto pr-1">
                  {preview.candidates.map((candidate) => (
                    <CandidateRow
                      candidate={candidate}
                      key={candidate.line}
                      onOverride={setOverride}
                      onToggle={toggle}
                      override={overrides.get(candidate.line) ?? ""}
                      problem={problems.find(
                        (entry) => entry.line === candidate.line
                      )}
                      selectionLimitReached={
                        selectionCount >= MAXIMUM_SUBSCRIPTION_SELECTION &&
                        !selected.has(candidate.line)
                      }
                      selected={selected.has(candidate.line)}
                    />
                  ))}
                </div>
              </>
            ) : (
              <Alert>
                <AlertDescription>
                  {newServersOnly &&
                  (preview.document_kind === "link_list" ||
                    preview.document_kind === "base64_link_list")
                    ? t("subscriptions.noNewServers")
                    : t(
                        `transports.subscriptionImport.documentKind.${preview.document_kind}`
                      )}
                </AlertDescription>
              </Alert>
            )}
            {previewExpired ? (
              <Alert variant="destructive">
                <AlertDescription className="flex flex-wrap items-center gap-2">
                  {t("transports.subscriptionImport.expired")}
                  <Button onClick={refetchExpired} size="sm" variant="outline">
                    {t("transports.subscriptionImport.expiredRefetch")}
                  </Button>
                </AlertDescription>
              </Alert>
            ) : applyMutation.error ? (
              <Alert variant="destructive">
                <AlertDescription>
                  <OperationErrorMessage error={applyMutation.error} />
                </AlertDescription>
              </Alert>
            ) : null}
            {problems.length > 0 ? (
              // The per-row explanations live inside a scroll area; the
              // disabled apply button must not leave its reason out of view.
              <p className="text-xs text-destructive">
                {t("transports.subscriptionImport.problemsSummary", {
                  count: problems.length,
                })}
              </p>
            ) : null}
          </div>
        ) : (
          <div className="space-y-3">
            {newServersOnly ? (
              <p
                className="flex items-center gap-2 text-sm text-muted-foreground"
                role="status"
              >
                {previewMutation.isPending ? (
                  <LoaderCircleIcon className="size-4 animate-spin" />
                ) : null}
                {previewMutation.error
                  ? t("subscriptions.refreshFailed")
                  : t("subscriptions.loading")}
              </p>
            ) : (
              <>
                <Input
                  autoFocus
                  onChange={(event) => setUrl(event.target.value)}
                  onKeyDown={(event) => {
                    // The same guard the Fetch button has: each Enter would start
                    // another provider fetch and another credential-holding
                    // preview session on the daemon.
                    if (
                      event.key === "Enter" &&
                      url.trim() &&
                      !previewMutation.isPending
                    ) {
                      fetchPreview()
                    }
                  }}
                  placeholder={t(
                    "transports.subscriptionImport.urlPlaceholder"
                  )}
                  value={url}
                />
                <p className="text-xs text-muted-foreground">
                  {t("transports.subscriptionImport.urlHint")}
                </p>
              </>
            )}
            {previewMutation.error ? (
              <Alert variant="destructive">
                <AlertDescription>
                  <OperationErrorMessage
                    error={previewMutation.error}
                    summary={
                      newServersOnly && previewError?.status === 404
                        ? t("subscriptions.targetMissing")
                        : previewReason
                          ? t(
                              `transports.subscriptionImport.urlRefused.${previewReason}`
                            )
                          : undefined
                    }
                  />
                </AlertDescription>
              </Alert>
            ) : null}
          </div>
        )}

        <DialogFooter>
          <Button
            disabled={applyMutation.isPending}
            onClick={() => close(false)}
            variant="outline"
          >
            {results
              ? t("transports.subscriptionImport.done")
              : t("common.cancel")}
          </Button>
          {results ? null : preview ? (
            <Button
              disabled={
                selectionCount === 0 ||
                problems.length > 0 ||
                applyMutation.isPending
              }
              onClick={apply}
            >
              {applyMutation.isPending ? (
                <>
                  <LoaderCircleIcon className="animate-spin" />
                  {t("transports.subscriptionImport.applying")}
                </>
              ) : (
                t("transports.subscriptionImport.apply", {
                  count: selectionCount,
                })
              )}
            </Button>
          ) : (
            <Button
              disabled={
                (!newServersOnly && !url.trim()) || previewMutation.isPending
              }
              onClick={() => fetchPreview(newServersOnly ? seed : undefined)}
            >
              {t("transports.subscriptionImport.fetch")}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function CandidateRow({
  candidate,
  onOverride,
  onToggle,
  override,
  problem,
  selectionLimitReached,
  selected,
}: {
  candidate: SubscriptionPreviewCandidate
  onOverride: (line: number, value: string) => void
  onToggle: (line: number) => void
  override: string
  problem?: { kind: string }
  selectionLimitReached: boolean
  selected: boolean
}) {
  const { t } = useTranslation()
  const selectable = isSelectable(candidate)
  const conflicted = requiresTagOverride(candidate)
  const label =
    candidate.remark?.trim() ||
    candidate.endpoint?.trim() ||
    t("transports.subscriptionImport.unnamed", { line: candidate.line })

  return (
    <div
      className={cn(
        "rounded-[4px] border px-3 py-2",
        !selectable && "opacity-60",
        problem &&
          "border-destructive bg-destructive/5 ring-1 ring-destructive/20"
      )}
    >
      <div className="flex items-center gap-2.5">
        <Checkbox
          aria-label={label}
          checked={selected && selectable}
          disabled={!selectable || selectionLimitReached}
          onCheckedChange={() => onToggle(candidate.line)}
        />
        <div className="min-w-0 flex-1">
          <div className="truncate text-sm font-medium">{label}</div>
          <div className="truncate text-xs text-muted-foreground">
            {[candidate.scheme, candidate.endpoint].filter(Boolean).join(" · ")}
          </div>
        </div>
        <DispositionBadge candidate={candidate} />
      </div>
      {selectable && selected ? (
        <div className="mt-2 flex items-center gap-2 pl-7">
          <label
            className="text-xs text-muted-foreground"
            htmlFor={`subscription-tag-${candidate.line}`}
          >
            {t("transports.subscriptionImport.tagLabel")}
          </label>
          <Input
            aria-describedby={
              problem ? `subscription-tag-problem-${candidate.line}` : undefined
            }
            aria-invalid={problem ? true : undefined}
            className={cn(
              "h-7 max-w-48 font-mono text-xs",
              problem && "border-destructive ring-2 ring-destructive/20"
            )}
            id={`subscription-tag-${candidate.line}`}
            onChange={(event) => onOverride(candidate.line, event.target.value)}
            // A conflicted tag has no usable default - the suggestion is the
            // very name that collides - so it stays a placeholder the operator
            // must replace. Elsewhere an empty field means "use the
            // suggestion", and the field shows exactly what will be sent.
            placeholder={candidate.suggested_tag ?? ""}
            value={
              conflicted
                ? override
                : override || (candidate.suggested_tag ?? "")
            }
          />
          {problem ? (
            <span
              className="text-xs text-destructive"
              id={`subscription-tag-problem-${candidate.line}`}
            >
              {t(`transports.subscriptionImport.problems.${problem.kind}`)}
            </span>
          ) : null}
        </div>
      ) : null}
    </div>
  )
}

function DispositionBadge({
  candidate,
}: {
  candidate: SubscriptionPreviewCandidate
}) {
  const { t } = useTranslation()
  if (candidate.disposition === "importable") {
    return null
  }
  return (
    <Badge variant="secondary">
      {t(
        `transports.subscriptionImport.dispositions.${candidate.disposition}`,
        candidate.disposition === "duplicate_in_document"
          ? { line: candidate.duplicate_of }
          : undefined
      )}
    </Badge>
  )
}

export function ResultsView({
  results,
}: {
  results: SubscriptionApplyResponse
}) {
  const { t } = useTranslation()
  // Three outcomes, not two. An entry an earlier apply already created is not
  // a failure: nothing went wrong and there is nothing to fix. Painting it red
  // teaches the operator to distrust the report, which costs more than the
  // line is worth.
  const created = results.results.filter(
    (result) => result.outcome === "created"
  )
  const alreadyImported = results.results.filter(
    (result) => result.outcome === "already_imported"
  )
  const failed = results.results.filter((result) => result.outcome === "failed")

  return (
    <div className="space-y-2">
      {created.length > 0 ? (
        <Alert>
          <CheckCircle2Icon />
          <AlertDescription>
            {t("transports.subscriptionImport.createdSummary", {
              count: created.length,
            })}
          </AlertDescription>
        </Alert>
      ) : null}
      {alreadyImported.length > 0 ? (
        <Alert>
          <InfoIcon />
          <AlertDescription>
            {t("transports.subscriptionImport.alreadyImportedSummary", {
              count: alreadyImported.length,
            })}
          </AlertDescription>
        </Alert>
      ) : null}
      {failed.map((result) => (
        <Alert key={result.line} variant="destructive">
          <XCircleIcon />
          <AlertDescription>
            {t("transports.subscriptionImport.failedEntry", {
              line: result.line,
              tag: result.tag ?? "",
            })}
            <OperationErrorMessage
              error={{
                message: result.error ?? "",
                details: { code: result.code },
              }}
            />
          </AlertDescription>
        </Alert>
      ))}
      {created.length > 0 ? (
        <p className="text-xs text-muted-foreground">
          {t("transports.subscriptionImport.nextSteps")}
        </p>
      ) : null}
    </div>
  )
}

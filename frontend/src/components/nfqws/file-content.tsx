import { useTranslation } from "react-i18next"

import { CodeEditor } from "@/components/shared/code-editor"
import { OperationErrorMessage } from "@/components/shared/operation-error-message"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"

export type NfqwsFileContentResponse = {
  content: string
  truncated?: boolean
}

export function NfqwsFileContent({
  data,
  draftContent,
  error,
  loading,
  onChange,
  onRetry,
  readonly,
}: {
  data?: NfqwsFileContentResponse
  draftContent?: string
  error: unknown
  loading: boolean
  onChange: (value: string) => void
  onRetry: () => void
  readonly: boolean
}) {
  const { t } = useTranslation()
  const loadError = error ? (
    <Alert variant="destructive">
      <AlertDescription className="space-y-3">
        <OperationErrorMessage
          error={error}
          fallbackSummary={t("nfqws.fileLoadFailed")}
        />
        <Button onClick={onRetry} variant="outline">
          {t("common.retry")}
        </Button>
      </AlertDescription>
    </Alert>
  ) : null

  // Never turn a failed load into a blank editable file. A user's existing
  // draft remains visible and editable if a later refresh fails.
  if (draftContent === undefined) {
    if (loadError) return loadError
    if (loading) {
      return (
        <Skeleton className="h-[40vh] max-h-[36rem] min-h-[16rem] w-full" />
      )
    }
  }
  return (
    <>
      {loadError}
      {readonly && data?.truncated && !error ? (
        <p className="text-sm text-muted-foreground" role="status">
          {t("nfqws.logTailShown")}
        </p>
      ) : null}
      <CodeEditor
        className="h-[50vh] max-h-[40rem] min-h-[18rem]"
        onChange={onChange}
        readOnly={readonly}
        syntax={readonly ? "log" : "nfqws"}
        value={draftContent ?? data?.content ?? ""}
      />
    </>
  )
}

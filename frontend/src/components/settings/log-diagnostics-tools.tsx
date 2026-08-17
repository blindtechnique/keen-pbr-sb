import {
  DownloadIcon,
  LoaderCircleIcon,
  RefreshCwIcon,
  ScrollTextIcon,
} from "lucide-react"
import { useCallback, useEffect, useRef, useState } from "react"

import { CodeEditor } from "@/components/shared/code-editor"
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
import { Label } from "@/components/ui/label"
import {
  collectLogDiagnostics,
  errorText,
  loadLogTail,
  type FetchLike,
} from "@/components/settings/log-diagnostics-tools-model"
import { downloadJson, formatDownloadTimestamp } from "@/lib/download"
import { cn } from "@/lib/utils"

export type LogDiagnosticsToolsLabels = {
  openLogAction: string
  downloadDiagnosticsAction: string
  downloadingDiagnosticsAction: string
  logDialogTitle: string
  logDialogDescription: string
  logEditorAriaLabel: string
  refreshLogAction: string
  refreshingLogAction: string
  closeAction: string
  logLoading: string
  logEmpty: string
  logLoadFailed: string
  diagnosticsDownloadFailed: string
  diagnosticsDialogTitle: string
  diagnosticsDialogDescription: string
  diagnosticsTrustWarning: string
  diagnosticsIncludeLists: string
  diagnosticsConfirmAction: string
}

export type LogDiagnosticsToolsProps = {
  labels: LogDiagnosticsToolsLabels
  className?: string
  fetcher?: FetchLike
  now?: () => Date
  diagnosticsFilenamePrefix?: string
}

const defaultFetch: FetchLike = (input, init) => fetch(input, init)
const systemNow = () => new Date()

export function LogDiagnosticsTools({
  labels,
  className,
  fetcher = defaultFetch,
  now = systemNow,
  diagnosticsFilenamePrefix = "keen-pbr-sb-diagnostics",
}: LogDiagnosticsToolsProps) {
  const [logDialogOpen, setLogDialogOpen] = useState(false)
  const [logText, setLogText] = useState<string | null>(null)
  const [logError, setLogError] = useState<string | null>(null)
  const [logLoading, setLogLoading] = useState(false)
  const [diagnosticsLoading, setDiagnosticsLoading] = useState(false)
  const [diagnosticsError, setDiagnosticsError] = useState<string | null>(null)
  const [diagnosticsDialogOpen, setDiagnosticsDialogOpen] = useState(false)
  const [includeListContents, setIncludeListContents] = useState(false)
  const logRequest = useRef<AbortController | null>(null)
  const logRequestSequence = useRef(0)

  useEffect(
    () => () => {
      logRequest.current?.abort()
    },
    []
  )

  const refreshLog = useCallback(async () => {
    logRequest.current?.abort()
    const controller = new AbortController()
    const sequence = logRequestSequence.current + 1
    logRequest.current = controller
    logRequestSequence.current = sequence
    setLogLoading(true)
    setLogError(null)

    try {
      const log = await loadLogTail(fetcher, controller.signal)
      if (logRequestSequence.current === sequence) {
        setLogText(log.lines.join("\n"))
      }
    } catch (error) {
      if (
        !controller.signal.aborted &&
        logRequestSequence.current === sequence
      ) {
        setLogError(errorText(error))
      }
    } finally {
      if (logRequestSequence.current === sequence) {
        setLogLoading(false)
      }
    }
  }, [fetcher])

  const openLog = () => {
    setLogDialogOpen(true)
    void refreshLog()
  }

  const closeLog = () => {
    logRequest.current?.abort()
    setLogDialogOpen(false)
  }

  const downloadDiagnostics = async () => {
    const generatedAt = now()
    setDiagnosticsLoading(true)
    setDiagnosticsError(null)

    try {
      const diagnostics = await collectLogDiagnostics({
        fetcher,
        generatedAt,
        includeListContents,
      })
      downloadJson(
        `${diagnosticsFilenamePrefix}-${formatDownloadTimestamp(generatedAt)}.json`,
        diagnostics
      )
      setDiagnosticsDialogOpen(false)
    } catch (error) {
      setDiagnosticsError(errorText(error))
    } finally {
      setDiagnosticsLoading(false)
    }
  }

  const editorValue =
    logText === null
      ? logLoading
        ? labels.logLoading
        : labels.logEmpty
      : logText || labels.logEmpty

  return (
    <>
      <div className={cn("flex flex-wrap gap-2", className)}>
        <Button onClick={openLog} type="button" variant="outline">
          <ScrollTextIcon />
          {labels.openLogAction}
        </Button>
        <Button
          disabled={diagnosticsLoading}
          onClick={() => {
            setDiagnosticsError(null)
            setDiagnosticsDialogOpen(true)
          }}
          type="button"
          variant="outline"
        >
          {diagnosticsLoading ? (
            <LoaderCircleIcon className="animate-spin" />
          ) : (
            <DownloadIcon />
          )}
          {diagnosticsLoading
            ? labels.downloadingDiagnosticsAction
            : labels.downloadDiagnosticsAction}
        </Button>
      </div>

      <Dialog
        open={logDialogOpen}
        onOpenChange={(open) => {
          if (!open) {
            closeLog()
          }
        }}
      >
        <DialogContent
          className="grid max-h-[calc(100dvh-2rem)] grid-rows-[auto_minmax(0,1fr)_auto] gap-4 overflow-hidden sm:max-w-4xl"
          showCloseButton={false}
        >
          <DialogHeader>
            <DialogTitle>{labels.logDialogTitle}</DialogTitle>
            <DialogDescription>{labels.logDialogDescription}</DialogDescription>
          </DialogHeader>

          <div className="min-h-0 space-y-2">
            {logError ? (
              <p className="text-sm text-destructive" role="alert">
                {labels.logLoadFailed}: {logError}
              </p>
            ) : null}
            <CodeEditor
              aria-label={labels.logEditorAriaLabel}
              className="h-[min(60dvh,36rem)] min-h-[18rem]"
              readOnly
              syntax="log"
              value={editorValue}
            />
          </div>

          <DialogFooter>
            <Button onClick={closeLog} type="button" variant="outline">
              {labels.closeAction}
            </Button>
            <Button
              disabled={logLoading}
              onClick={() => void refreshLog()}
              type="button"
            >
              {logLoading ? (
                <LoaderCircleIcon className="animate-spin" />
              ) : (
                <RefreshCwIcon />
              )}
              {logLoading
                ? labels.refreshingLogAction
                : labels.refreshLogAction}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog
        open={diagnosticsDialogOpen}
        onOpenChange={(open) => {
          if (!diagnosticsLoading) {
            setDiagnosticsDialogOpen(open)
          }
        }}
      >
        <DialogContent showCloseButton={!diagnosticsLoading}>
          <DialogHeader>
            <DialogTitle>{labels.diagnosticsDialogTitle}</DialogTitle>
            <DialogDescription>
              {labels.diagnosticsDialogDescription}
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-3 text-sm">
            <p className="text-muted-foreground">
              {labels.diagnosticsTrustWarning}
            </p>
            <Label className="flex cursor-pointer items-start gap-2">
              <Checkbox
                checked={includeListContents}
                disabled={diagnosticsLoading}
                onCheckedChange={(checked) =>
                  setIncludeListContents(Boolean(checked))
                }
              />
              <span>{labels.diagnosticsIncludeLists}</span>
            </Label>
            {diagnosticsError ? (
              <p className="text-destructive" role="alert">
                {labels.diagnosticsDownloadFailed}: {diagnosticsError}
              </p>
            ) : null}
          </div>

          <DialogFooter>
            <Button
              disabled={diagnosticsLoading}
              onClick={() => setDiagnosticsDialogOpen(false)}
              type="button"
              variant="outline"
            >
              {labels.closeAction}
            </Button>
            <Button
              disabled={diagnosticsLoading}
              onClick={() => void downloadDiagnostics()}
              type="button"
            >
              {diagnosticsLoading ? (
                <LoaderCircleIcon className="animate-spin" />
              ) : (
                <DownloadIcon />
              )}
              {diagnosticsLoading
                ? labels.downloadingDiagnosticsAction
                : labels.diagnosticsConfirmAction}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import {
  DownloadIcon,
  ExternalLinkIcon,
  FilePlusIcon,
  LoaderCircleIcon,
  PlayIcon,
  RefreshCwIcon,
  RotateCcwIcon,
  SaveIcon,
  TrashIcon,
  UploadIcon,
} from "lucide-react"
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"

import { PageHeader } from "@/components/shared/page-header"
import { KeeneticStatus } from "@/components/shared/keenetic-status"
import { SectionTabs, type SectionTab } from "@/components/shared/section-tabs"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Checkbox } from "@/components/ui/checkbox"
import { CodeEditor } from "@/components/shared/code-editor"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  formatNfqwsConfig,
  parseNfqwsConfig,
  type NfqwsConfigForm,
} from "@/lib/nfqws-config"
import { formatDownloadTimestamp } from "@/lib/download"
import {
  InvalidNfqwsBackupError,
  NfqwsBackupScopeMissingError,
  createNfqwsBackupSelection,
  hasNfqwsBackupFiles,
  parseNfqwsBackupBundle,
  selectNfqwsBackupBundle,
  selectNfqwsBackupFiles,
  type NfqwsBackupScope,
} from "@/lib/nfqws-backup"
import {
  createBackup,
  downloadBackup,
  InvalidBackupBundleError,
  parseBackupBundle,
  restoreBackup as restoreBackupBundle,
  rollbackBackup,
  type BackupSelection,
} from "@/lib/backup"
import {
  NFQWS_UPDATE_QUERY_KEY,
  nfqwsAction,
  nfqwsUpdateQueryOptions,
  type NfqwsActionResult,
  type NfqwsUpdateStatus,
} from "@/api/nfqws"
import { cn } from "@/lib/utils"

type NfqwsFile = {
  name: string
  category: "config" | "list" | "lua" | "log"
  removable: boolean
  size: number
}
type Strategy = {
  name: string
  builtin: boolean
  overridden: boolean
  content: string
}
type Status = {
  installed: boolean
  running: boolean
  process_running: boolean
  queue_active: boolean
  version: string
  files: NfqwsFile[]
  strategies: Strategy[]
  active_strategy: string
}
const NFQWS_TAB_VALUES = [
  "settings",
  "strategies",
  "lists",
  "lua",
  "logs",
  "check",
] as const

type Tab = (typeof NFQWS_TAB_VALUES)[number]

type OperationState = {
  open: boolean
  pending: boolean
  success?: boolean
  title: string
  output: string
  rollbackAvailable: boolean
}

type DraftFile = {
  category: "list" | "lua"
  name: string
  content: string
}

type RunOperation = (
  title: string,
  operation: () => Promise<NfqwsActionResult>,
  successMessage: string,
  rollbackAvailable?: boolean
) => Promise<boolean>

export function NfqwsPage() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const query = useQuery<Status>({
    queryKey: ["nfqws"],
    queryFn: async () => {
      const response = await fetch("/api/nfqws")
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      return response.json()
    },
    refetchInterval: 10_000,
  })
  const status = query.data
  const backupImportRef = useRef<HTMLInputElement>(null)
  const [backupOpen, setBackupOpen] = useState(false)
  const [backupImportScope, setBackupImportScope] =
    useState<NfqwsBackupScope>("all")
  const [backupPending, setBackupPending] = useState<{
    action: "download" | "restore"
    scope: NfqwsBackupScope
  } | null>(null)
  const [backupRevision, setBackupRevision] = useState(0)
  const [configDirty, setConfigDirty] = useState(false)
  const [strategyDirty, setStrategyDirty] = useState(false)
  const [refreshPending, setRefreshPending] = useState(false)
  const [tab, setTab] = useState<Tab>("settings")
  const [upgradeOpen, setUpgradeOpen] = useState(false)
  const [downloadUpgradeBackup, setDownloadUpgradeBackup] = useState(true)
  const [drafts, setDrafts] = useState<Record<string, DraftFile>>({})
  const [operation, setOperation] = useState<OperationState>({
    open: false,
    pending: false,
    title: "",
    output: "",
    rollbackAvailable: false,
  })
  const serviceToggleMutation = useMutation({
    mutationFn: (payload: Record<string, unknown>) => nfqwsAction(payload),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["nfqws"] })
    },
    onError: (error) => toast.error(error.message, { richColors: true }),
  })
  const updateQuery = useQuery({
    ...nfqwsUpdateQueryOptions(),
    enabled: status?.installed === true,
  })

  const runOperation: RunOperation = async (
    title,
    execute,
    successMessage,
    rollbackAvailable = false
  ) => {
    setOperation({
      open: true,
      pending: true,
      title,
      output: t("nfqws.operationRunning"),
      rollbackAvailable: false,
    })
    try {
      const result = await execute()
      await queryClient.invalidateQueries({ queryKey: ["nfqws"] })
      const output = result.output?.trim() || successMessage
      setOperation({
        open: true,
        pending: false,
        success: true,
        title,
        output: result.strategy_created
          ? `${output}\n\n${t("nfqws.defaultStrategyCreated", {
              name: result.strategy_created,
            })}`
          : output,
        rollbackAvailable,
      })
      return true
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      setOperation({
        open: true,
        pending: false,
        success: false,
        title,
        output: message,
        rollbackAvailable,
      })
      return false
    }
  }

  const runUpgrade = async () => {
    setUpgradeOpen(false)
    if (downloadUpgradeBackup) {
      const groups: BackupSelection = {
        general: false,
        transports: false,
        outbounds: false,
        dns: false,
        routing: false,
        nfqws_config: true,
        nfqws_lists: true,
      }
      try {
        const backup = await createBackup(groups)
        downloadBackup(
          backup,
          `keen-pbr-sb-nfqws-before-update-${formatDownloadTimestamp()}.json`
        )
      } catch (error) {
        setOperation({
          open: true,
          pending: false,
          success: false,
          title: t("nfqws.upgrade"),
          output: error instanceof Error ? error.message : String(error),
          rollbackAvailable: false,
        })
        return
      }
    }
    const completed = await runOperation(
      t("nfqws.upgrade"),
      () => nfqwsAction({ action: "upgrade" }),
      t("nfqws.operationCompleted"),
      true
    )
    if (completed) {
      try {
        const latest = await nfqwsAction<NfqwsUpdateStatus>({
          action: "check_update",
          force: true,
        })
        queryClient.setQueryData(NFQWS_UPDATE_QUERY_KEY, latest)
      } catch {
        await queryClient.invalidateQueries({
          queryKey: NFQWS_UPDATE_QUERY_KEY,
        })
      }
    }
  }

  const refreshAll = async () => {
    setRefreshPending(true)
    try {
      const refreshed = await query.refetch()
      if (!refreshed.data?.installed) {
        toast.info(t("nfqws.notInstalled.title"))
        return
      }
      const latest = await nfqwsAction<NfqwsUpdateStatus>({
        action: "check_update",
        force: true,
      })
      queryClient.setQueryData(NFQWS_UPDATE_QUERY_KEY, latest)
      if (latest.available) {
        toast.success(t("nfqws.updateAvailable", { version: latest.latest }))
      } else {
        toast.success(t("nfqws.upToDate"))
      }
    } catch (error) {
      await queryClient.invalidateQueries({
        queryKey: NFQWS_UPDATE_QUERY_KEY,
      })
      toast.error(
        error instanceof Error ? error.message : t("nfqws.operationFailed"),
        { richColors: true }
      )
    } finally {
      setRefreshPending(false)
    }
  }

  const saveDrafts = async (restart: boolean) => {
    const files = Object.values(drafts)
    if (files.length === 0) return
    const completed = await runOperation(
      restart ? t("nfqws.saveAndRestart") : t("nfqws.saveDrafts"),
      () => nfqwsAction({ action: "save_files", files, restart }),
      t("nfqws.saved")
    )
    if (completed) {
      setDrafts({})
      await queryClient.invalidateQueries({ queryKey: ["nfqws", "file"] })
    }
  }
  const listDraftCount = Object.values(drafts).filter(
    (draft) => draft.category === "list"
  ).length
  const luaDraftCount = Object.values(drafts).filter(
    (draft) => draft.category === "lua"
  ).length
  const configScopeDirty = configDirty || strategyDirty || luaDraftCount > 0
  const scopeHasDrafts = (scope: NfqwsBackupScope) =>
    (scope !== "list" && configScopeDirty) ||
    (scope !== "config" && listDraftCount > 0)

  const exportBackup = async (scope: NfqwsBackupScope) => {
    setBackupPending({ action: "download", scope })
    try {
      const suffix =
        scope === "config" ? "config" : scope === "list" ? "lists" : "all"
      downloadBackup(
        selectNfqwsBackupBundle(
          await createBackup(createNfqwsBackupSelection(scope)),
          scope
        ),
        `keen-pbr-sb-nfqws-${suffix}-${formatDownloadTimestamp()}.json`
      )
      toast.success(t("nfqws.backup.downloaded"))
    } catch (error) {
      toast.error(
        error instanceof Error
          ? error.message
          : t("configTransfer.exportFailed"),
        { richColors: true }
      )
    } finally {
      setBackupPending(null)
    }
  }

  const chooseBackup = (scope: NfqwsBackupScope) => {
    if (scopeHasDrafts(scope)) {
      toast.error(t("nfqws.backup.unsavedBlocked"), { richColors: true })
      return
    }
    setBackupImportScope(scope)
    backupImportRef.current?.click()
  }

  const restoreBackup = async (file?: File) => {
    if (!file) return
    const scope = backupImportScope
    if (scopeHasDrafts(scope)) {
      toast.error(t("nfqws.backup.unsavedBlocked"), { richColors: true })
      if (backupImportRef.current) backupImportRef.current.value = ""
      return
    }

    setBackupPending({ action: "restore", scope })
    try {
      const parsed: unknown = JSON.parse(await file.text())
      let execute: () => Promise<NfqwsActionResult>
      try {
        const bundle = selectNfqwsBackupBundle(parseBackupBundle(parsed), scope)
        execute = async () => {
          await restoreBackupBundle(bundle)
          return { ok: true, output: t("nfqws.backup.restored") }
        }
      } catch (error) {
        if (!(error instanceof InvalidBackupBundleError)) throw error
        const legacyBundle = parseNfqwsBackupBundle(parsed)
        const files = selectNfqwsBackupFiles(legacyBundle.files, scope)
        if (!hasNfqwsBackupFiles(files)) {
          throw new NfqwsBackupScopeMissingError()
        }
        execute = async () => {
          await nfqwsAction({ action: "import_bundle", files })
          const restarted = await nfqwsAction<NfqwsActionResult>({
            action: "service",
            command: "restart",
          })
          return {
            ...restarted,
            output: [t("nfqws.backup.restored"), restarted.output?.trim()]
              .filter(Boolean)
              .join("\n\n"),
          }
        }
      }

      setBackupOpen(false)
      const completed = await runOperation(
        t("nfqws.backup.restoreTitle"),
        execute,
        t("nfqws.backup.restored")
      )
      if (completed) {
        await queryClient.invalidateQueries({ queryKey: ["nfqws", "file"] })
        setBackupRevision((revision) => revision + 1)
      }
    } catch (error) {
      const message =
        error instanceof NfqwsBackupScopeMissingError
          ? t("nfqws.backup.scopeMissing")
          : error instanceof InvalidBackupBundleError ||
              error instanceof InvalidNfqwsBackupError ||
              error instanceof SyntaxError
            ? t("configTransfer.invalidFormat")
            : error instanceof Error
              ? error.message
              : t("configTransfer.invalidFormat")
      toast.error(message, { richColors: true })
    } finally {
      setBackupPending(null)
      if (backupImportRef.current) backupImportRef.current.value = ""
    }
  }
  const nfqwsTabs: SectionTab<Tab>[] = NFQWS_TAB_VALUES.map((value) => ({
    value,
    label: t(`nfqws.tabs.${value}`),
  }))

  return (
    <div className="space-y-3">
      <PageHeader
        actions={
          <div className="flex flex-wrap gap-2">
            <Button
              disabled={!status?.installed || backupPending !== null}
              onClick={() => setBackupOpen(true)}
              variant="outline"
            >
              <DownloadIcon />
              {t("nfqws.backup.button")}
            </Button>
            <input
              accept="application/json,.json"
              className="hidden"
              onChange={(event) => void restoreBackup(event.target.files?.[0])}
              ref={backupImportRef}
              type="file"
            />
            <Button
              disabled={
                query.isFetching || updateQuery.isFetching || refreshPending
              }
              onClick={() => void refreshAll()}
              variant="outline"
            >
              <RefreshCwIcon
                className={
                  query.isFetching || updateQuery.isFetching || refreshPending
                    ? "animate-spin"
                    : ""
                }
              />
              {t("nfqws.refresh")}
            </Button>
          </div>
        }
        description={t("nfqws.description")}
        title={
          <a
            aria-label={t("nfqws.repository")}
            className="inline-flex items-center gap-1.5 text-inherit no-underline outline-none hover:text-inherit hover:no-underline focus-visible:ring-2 focus-visible:ring-ring"
            href="https://github.com/nfqws/nfqws2-keenetic"
            rel="noreferrer"
            target="_blank"
          >
            nfqws2
            <ExternalLinkIcon className="size-4" />
          </a>
        }
      />

      {!status?.installed && !query.isLoading ? <NotInstalled /> : null}

      {status?.installed ? (
        <>
          <NfqwsSection
            title={t("nfqws.service")}
            description={t("nfqws.version", {
              version: status.version || "—",
            })}
            action={
              <div className="flex flex-wrap items-center justify-end gap-2">
                <KeeneticStatus
                  tone={updateQuery.data?.available ? "success" : "neutral"}
                >
                  {updateQuery.data?.available
                    ? t("common.updateStatus.available")
                    : updateQuery.data
                      ? t("common.updateStatus.current")
                      : t("common.updateStatus.checking")}
                </KeeneticStatus>
                <KeeneticStatus
                  tone={status.running ? "success" : "neutral"}
                >
                  {status.running ? t("nfqws.running") : t("nfqws.stopped")}
                </KeeneticStatus>
              </div>
            }
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <label className="flex cursor-pointer items-center gap-2">
                <Switch
                  aria-label={
                    status.running ? t("nfqws.stop") : t("nfqws.start")
                  }
                  checked={status.running}
                  disabled={
                    serviceToggleMutation.isPending || operation.pending
                  }
                  onCheckedChange={(checked) =>
                    serviceToggleMutation.mutate({
                      action: "service",
                      command: checked ? "start" : "stop",
                    })
                  }
                />
                <span className="text-sm text-muted-foreground">
                  {status.running ? t("nfqws.stop") : t("nfqws.start")}
                </span>
              </label>
              <div className="flex flex-wrap items-center gap-2">
                <Button
                  disabled={operation.pending}
                  onClick={() =>
                    void runOperation(
                      t("nfqws.restart"),
                      () =>
                        nfqwsAction({
                          action: "service",
                          command: "restart",
                        }),
                      t("nfqws.operationCompleted")
                    )
                  }
                  variant="outline"
                >
                  <RefreshCwIcon />
                  {t("nfqws.restart")}
                </Button>
                <Button
                  disabled={operation.pending}
                  onClick={() =>
                    void runOperation(
                      t("nfqws.reload"),
                      () =>
                        nfqwsAction({ action: "service", command: "reload" }),
                      t("nfqws.operationCompleted")
                    )
                  }
                  variant="outline"
                >
                  {t("nfqws.reload")}
                </Button>
                <Button
                  disabled={operation.pending || updateQuery.isFetching}
                  onClick={() => setUpgradeOpen(true)}
                  variant="outline"
                >
                  <DownloadIcon />
                  {t("nfqws.upgrade")}
                </Button>
              </div>
            </div>
          </NfqwsSection>

          <SectionTabs
            ariaLabel={t("nfqws.tabs.ariaLabel")}
            onValueChange={setTab}
            tabs={nfqwsTabs}
            value={tab}
          />

          {tab === "settings" ? (
            <SettingsEditor
              key={`settings-${backupRevision}`}
              onDirtyChange={setConfigDirty}
              status={status}
              refresh={() => void query.refetch()}
            />
          ) : null}
          {tab === "strategies" ? (
            <StrategiesEditor
              onDirtyChange={setStrategyDirty}
              refresh={() => void query.refetch()}
              runOperation={runOperation}
              status={status}
            />
          ) : null}
          {tab === "lists" ? (
            <FilesEditor
              category="list"
              drafts={drafts}
              files={status.files}
              onDraftChange={(draft) =>
                setDrafts((current) => ({
                  ...current,
                  [`${draft.category}/${draft.name}`]: draft,
                }))
              }
              onDraftRemove={(category, name) =>
                setDrafts((current) => {
                  const next = { ...current }
                  delete next[`${category}/${name}`]
                  return next
                })
              }
              onSaveDrafts={saveDrafts}
              refresh={() => void query.refetch()}
            />
          ) : null}
          {tab === "lua" ? (
            <FilesEditor
              category="lua"
              drafts={drafts}
              files={status.files}
              onDraftChange={(draft) =>
                setDrafts((current) => ({
                  ...current,
                  [`${draft.category}/${draft.name}`]: draft,
                }))
              }
              onDraftRemove={(category, name) =>
                setDrafts((current) => {
                  const next = { ...current }
                  delete next[`${category}/${name}`]
                  return next
                })
              }
              onSaveDrafts={saveDrafts}
              refresh={() => void query.refetch()}
            />
          ) : null}
          {tab === "logs" ? (
            <FilesEditor
              category="log"
              drafts={drafts}
              files={status.files}
              onDraftChange={() => undefined}
              onDraftRemove={() => undefined}
              onSaveDrafts={saveDrafts}
              refresh={() => void query.refetch()}
              readonly
            />
          ) : null}
          {tab === "check" ? <UrlCheck /> : null}

          <NfqwsOperationDialog
            onClose={() =>
              setOperation((current) => ({ ...current, open: false }))
            }
            onRollback={() =>
              void runOperation(
                t("nfqws.rollback"),
                async () => {
                  await rollbackBackup()
                  return { ok: true, output: t("nfqws.rollbackCompleted") }
                },
                t("nfqws.rollbackCompleted")
              )
            }
            operation={operation}
          />
          <NfqwsUpgradeDialog
            downloadBackup={downloadUpgradeBackup}
            latest={updateQuery.data?.latest}
            onDownloadBackupChange={setDownloadUpgradeBackup}
            onOpenChange={setUpgradeOpen}
            onUpgrade={() => void runUpgrade()}
            open={upgradeOpen}
          />
          <NfqwsBackupDialog
            busy={backupPending}
            configDirty={configScopeDirty}
            listDraftCount={listDraftCount}
            onDownload={(scope) => void exportBackup(scope)}
            onOpenChange={setBackupOpen}
            onRestore={chooseBackup}
            open={backupOpen}
          />
        </>
      ) : null}
    </div>
  )
}

function NfqwsOperationDialog({
  onClose,
  onRollback,
  operation,
}: {
  onClose: () => void
  onRollback: () => void
  operation: OperationState
}) {
  const { t } = useTranslation()
  return (
    <Dialog
      onOpenChange={(open) => {
        if (!open && !operation.pending) onClose()
      }}
      open={operation.open}
    >
      <DialogContent
        className="overflow-hidden sm:max-w-2xl"
        showCloseButton={false}
      >
        <DialogHeader>
          <DialogTitle>{operation.title}</DialogTitle>
          <DialogDescription
            className={
              operation.pending
                ? undefined
                : operation.success
                  ? "text-emerald-700 dark:text-emerald-400"
                  : "text-destructive"
            }
          >
            {operation.pending
              ? t("nfqws.operationRunning")
              : operation.success
                ? t("nfqws.operationSucceeded")
                : t("nfqws.operationFailed")}
          </DialogDescription>
        </DialogHeader>
        <div className="relative h-[min(22rem,55dvh)] overflow-y-auto rounded-md border bg-muted/60 p-3 font-mono text-xs whitespace-pre-wrap text-foreground">
          {operation.pending ? (
            <LoaderCircleIcon className="mr-2 inline size-4 animate-spin" />
          ) : null}
          {operation.output}
        </div>
        <DialogFooter>
          {operation.rollbackAvailable && !operation.pending ? (
            <Button onClick={onRollback} variant="destructive">
              <RotateCcwIcon />
              {t("nfqws.rollback")}
            </Button>
          ) : null}
          <Button
            disabled={operation.pending}
            onClick={onClose}
            variant="outline"
          >
            {t("nfqws.closeResult")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function NfqwsBackupDialog({
  busy,
  configDirty,
  listDraftCount,
  onDownload,
  onOpenChange,
  onRestore,
  open,
}: {
  busy: {
    action: "download" | "restore"
    scope: NfqwsBackupScope
  } | null
  configDirty: boolean
  listDraftCount: number
  onDownload: (scope: NfqwsBackupScope) => void
  onOpenChange: (open: boolean) => void
  onRestore: (scope: NfqwsBackupScope) => void
  open: boolean
}) {
  const { t } = useTranslation()
  const rows: {
    scope: NfqwsBackupScope
    title: string
    description: string
  }[] = [
    {
      scope: "config",
      title: t("nfqws.backup.configTitle"),
      description: t("nfqws.backup.configDescription"),
    },
    {
      scope: "list",
      title: t("nfqws.backup.listsTitle"),
      description: t("nfqws.backup.listsDescription"),
    },
    {
      scope: "all",
      title: t("nfqws.backup.allTitle"),
      description: t("nfqws.backup.allDescription"),
    },
  ]
  const isBlocked = (scope: NfqwsBackupScope) =>
    (scope !== "list" && configDirty) ||
    (scope !== "config" && listDraftCount > 0)

  return (
    <Dialog
      onOpenChange={(nextOpen) => {
        if (!nextOpen && busy) return
        onOpenChange(nextOpen)
      }}
      open={open}
    >
      <DialogContent
        className="overflow-hidden max-sm:top-auto max-sm:bottom-0 max-sm:left-0 max-sm:max-h-[calc(100dvh-0.75rem)] max-sm:max-w-none max-sm:translate-x-0 max-sm:translate-y-0 max-sm:rounded-b-none max-sm:border-x-0 max-sm:border-b-0 sm:max-w-2xl"
        showCloseButton={!busy}
      >
        <DialogHeader>
          <DialogTitle>{t("nfqws.backup.title")}</DialogTitle>
          <DialogDescription>{t("nfqws.backup.description")}</DialogDescription>
        </DialogHeader>
        <div className="min-h-0 overflow-y-auto">
          <div className="divide-y">
            {rows.map(({ description, scope, title }) => {
              const blocked = isBlocked(scope)
              return (
                <div
                  className="flex flex-col gap-3 py-4 first:pt-0 last:pb-0 sm:flex-row sm:items-center sm:justify-between"
                  key={scope}
                >
                  <div className="min-w-0">
                    <p className="font-medium">{title}</p>
                    <p className="mt-1 text-sm text-muted-foreground">
                      {description}
                    </p>
                    {blocked ? (
                      <p className="mt-1 text-sm text-destructive">
                        {t("nfqws.backup.unsavedBlocked")}
                      </p>
                    ) : null}
                  </div>
                  <div className="flex shrink-0 flex-wrap gap-2 sm:justify-end">
                    <Button
                      disabled={busy !== null}
                      onClick={() => onDownload(scope)}
                      variant="outline"
                    >
                      {busy?.action === "download" && busy.scope === scope ? (
                        <LoaderCircleIcon className="animate-spin" />
                      ) : (
                        <DownloadIcon />
                      )}
                      {t("nfqws.backup.download")}
                    </Button>
                    <Button
                      disabled={busy !== null || blocked}
                      onClick={() => onRestore(scope)}
                      variant="outline"
                    >
                      {busy?.action === "restore" && busy.scope === scope ? (
                        <LoaderCircleIcon className="animate-spin" />
                      ) : (
                        <UploadIcon />
                      )}
                      {t("nfqws.backup.restore")}
                    </Button>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}

function NfqwsUpgradeDialog({
  downloadBackup,
  latest,
  onDownloadBackupChange,
  onOpenChange,
  onUpgrade,
  open,
}: {
  downloadBackup: boolean
  latest?: string
  onDownloadBackupChange: (checked: boolean) => void
  onOpenChange: (open: boolean) => void
  onUpgrade: () => void
  open: boolean
}) {
  const { t } = useTranslation()
  return (
    <Dialog onOpenChange={onOpenChange} open={open}>
      <DialogContent showCloseButton={false}>
        <DialogHeader>
          <DialogTitle>{t("nfqws.upgradeConfirmTitle")}</DialogTitle>
          <DialogDescription>
            {t("nfqws.upgradeConfirmDescription", { version: latest ?? "—" })}
          </DialogDescription>
        </DialogHeader>
        <Alert>
          <AlertTitle>{t("nfqws.automaticBackupTitle")}</AlertTitle>
          <AlertDescription>
            {t("nfqws.automaticBackupDescription")}
          </AlertDescription>
        </Alert>
        <label className="flex cursor-pointer items-start gap-3 rounded-md border p-3">
          <Checkbox
            checked={downloadBackup}
            onCheckedChange={(checked) =>
              onDownloadBackupChange(checked === true)
            }
          />
          <span className="text-sm">
            {t("nfqws.downloadBackupBeforeUpgrade")}
          </span>
        </label>
        <DialogFooter>
          <Button onClick={() => onOpenChange(false)} variant="outline">
            {t("common.cancel")}
          </Button>
          <Button onClick={onUpgrade}>
            <DownloadIcon />
            {t("nfqws.upgrade")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function NotInstalled() {
  const { t } = useTranslation()
  return (
    <Alert variant="destructive">
      <AlertTitle>{t("nfqws.notInstalled.title")}</AlertTitle>
      <AlertDescription className="space-y-3">
        <p>{t("nfqws.notInstalled.description")}</p>
        <div>
          <p className="mb-1 font-medium">
            {t("nfqws.notInstalled.ourInstaller")}
          </p>
          <code className="block overflow-x-auto rounded bg-muted p-2 text-xs text-foreground">
            sh -c &quot;$(curl -fsSL
            https://raw.githubusercontent.com/blindtechnique/keen-pbr-sb/main/install.sh)&quot;
          </code>
        </div>
        <div>
          <p className="mb-1 font-medium">{t("nfqws.notInstalled.original")}</p>
          <code className="block overflow-x-auto rounded bg-muted p-2 text-xs text-foreground">
            echo &quot;src/gz nfqws2-keenetic
            https://nfqws.github.io/nfqws2-keenetic/all&quot; &gt;
            /opt/etc/opkg/nfqws2-keenetic.conf &amp;&amp; opkg update &amp;&amp;
            opkg install nfqws2-keenetic
          </code>
        </div>
      </AlertDescription>
    </Alert>
  )
}

async function readFile(file: NfqwsFile) {
  return nfqwsAction<{ content: string }>({
    action: "read_file",
    category: file.category,
    name: file.name,
  })
}

function SettingsEditor({
  onDirtyChange,
  status,
  refresh,
}: {
  onDirtyChange: (dirty: boolean) => void
  status: Status
  refresh: () => void
}) {
  const { t } = useTranslation()
  const file = status.files.find(
    (item) => item.category === "config" && item.name === "nfqws2.conf"
  )
  const fileName = file?.name
  const [source, setSource] = useState("")
  const [form, setForm] = useState<NfqwsConfigForm | null>(null)
  const [baselineForm, setBaselineForm] = useState<NfqwsConfigForm | null>(null)
  useEffect(() => {
    if (fileName)
      void nfqwsAction<{ content: string }>({
        action: "read_file",
        category: "config",
        name: fileName,
      }).then(({ content }) => {
        const parsed = parseNfqwsConfig(content)
        setSource(content)
        setForm(parsed)
        setBaselineForm(parsed)
      })
  }, [fileName])
  const dirty =
    form !== null &&
    baselineForm !== null &&
    JSON.stringify(form) !== JSON.stringify(baselineForm)
  useEffect(() => {
    onDirtyChange(dirty)
  }, [dirty, onDirtyChange])
  useEffect(
    () => () => {
      onDirtyChange(false)
    },
    [onDirtyChange]
  )
  const save = async () => {
    if (!file || !form) return
    const nextSource = formatNfqwsConfig(source, form)
    await nfqwsAction({
      action: "save_file",
      category: "config",
      name: file.name,
      content: nextSource,
    })
    setSource(nextSource)
    setBaselineForm(form)
    toast.success(t("nfqws.saved"))
    refresh()
  }
  if (!file || !form)
    return (
      <Alert>
        <AlertDescription>{t("nfqws.configMissing")}</AlertDescription>
      </Alert>
    )
  const textFields: (keyof NfqwsConfigForm)[] = [
    "ISP_INTERFACE",
    "NFQWS_BASE_ARGS",
    "NFQWS_ARGS",
    "NFQWS_ARGS_QUIC",
    "NFQWS_ARGS_UDP",
    "NFQWS_ARGS_CUSTOM",
    "NFQWS_ARGS_IPSET",
    "TCP_PORTS",
    "UDP_PORTS",
    "POLICY_NAME",
  ]
  return (
    <NfqwsSection
      description={t("nfqws.settingsDescription")}
      title={t("nfqws.settingsTitle")}
    >
      <div className="space-y-4">
        {textFields.map((key) => (
          <div className="grid gap-1.5" key={key}>
            <Label>{key}</Label>
            {key.includes("ARGS") ? (
              <CodeEditor
                className="min-h-24"
                onChange={(next) => setForm({ ...form, [key]: next })}
                syntax="nfqws"
                value={String(form[key])}
              />
            ) : (
              <Input
                className="font-mono"
                onChange={(event) =>
                  setForm({ ...form, [key]: event.target.value })
                }
                value={String(form[key])}
              />
            )}
          </div>
        ))}
        <div className="grid gap-1.5">
          <Label>NFQWS_EXTRA_ARGS</Label>
          <select
            className="h-9 rounded-md border bg-background px-3"
            onChange={(event) =>
              setForm({
                ...form,
                NFQWS_EXTRA_ARGS: event.target
                  .value as NfqwsConfigForm["NFQWS_EXTRA_ARGS"],
              })
            }
            value={form.NFQWS_EXTRA_ARGS}
          >
            <option value="MODE_AUTO">MODE_AUTO</option>
            <option value="MODE_LIST">MODE_LIST</option>
            <option value="MODE_ALL">MODE_ALL</option>
          </select>
        </div>
        {(["IPV6_ENABLED", "POLICY_EXCLUDE", "LOG_LEVEL"] as const).map(
          (key) => (
            <label
              className="flex min-h-10 cursor-pointer items-center gap-3 py-1"
              key={key}
            >
              <Checkbox
                checked={form[key]}
                onCheckedChange={(checked) =>
                  setForm({ ...form, [key]: checked === true })
                }
              />
              <span className="text-sm">{key}</span>
            </label>
          )
        )}
        <div className="flex justify-end">
          <Button onClick={() => void save()}>
            <SaveIcon />
            {t("nfqws.save")}
          </Button>
        </div>
      </div>
    </NfqwsSection>
  )
}

function StrategiesEditor({
  onDirtyChange,
  refresh,
  runOperation,
  status,
}: {
  onDirtyChange: (dirty: boolean) => void
  refresh: () => void
  runOperation: RunOperation
  status: Status
}) {
  const { t } = useTranslation()
  const preferredStrategy =
    status.active_strategy || status.strategies[0]?.name || ""
  const [selected, setSelected] = useState(preferredStrategy)
  const [draftContent, setDraftContent] = useState<Record<string, string>>({})
  const dirty = Object.entries(draftContent).some(([name, content]) => {
    const persisted = status.strategies.find((item) => item.name === name)
    return persisted === undefined || persisted.content !== content
  })
  useEffect(() => {
    onDirtyChange(dirty)
  }, [dirty, onDirtyChange])
  useEffect(
    () => () => {
      onDirtyChange(false)
    },
    [onDirtyChange]
  )
  const effectiveSelected =
    status.strategies.some((item) => item.name === selected) ||
    Object.hasOwn(draftContent, selected)
      ? selected
      : preferredStrategy
  const strategy = status.strategies.find(
    (item) => item.name === effectiveSelected
  )
  const content = draftContent[effectiveSelected] ?? strategy?.content ?? ""
  const add = () => {
    const name = window.prompt(t("nfqws.strategyName"))
    if (name) {
      setSelected(name)
      setDraftContent((current) => ({ ...current, [name]: "" }))
    }
  }
  const run = async (action: string) => {
    if (action === "apply_strategy") {
      const completed = await runOperation(
        t("nfqws.applyStrategy"),
        () =>
          nfqwsAction({
            action,
            name: effectiveSelected,
            content,
          }),
        t("nfqws.strategyAppliedAndRestarted")
      )
      if (completed) refresh()
      return
    }
    try {
      await nfqwsAction<{ ok: boolean; output?: string }>({
        action,
        name: effectiveSelected,
        content,
      })
      if (action === "save_strategy" || action === "delete_strategy") {
        setDraftContent((current) => {
          const next = { ...current }
          delete next[effectiveSelected]
          return next
        })
      }
      toast.success(t("nfqws.saved"))
      refresh()
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      toast.error(message, { richColors: true })
    }
  }
  return (
    <NfqwsSection
      description={t("nfqws.strategiesDescription")}
      title={t("nfqws.strategiesTitle")}
    >
      <div className="space-y-4">
        <div className="flex flex-wrap gap-2">
          <select
            className="h-9 min-w-60 rounded-md border bg-background px-3"
            onChange={(event) => setSelected(event.target.value)}
            value={effectiveSelected}
          >
            {status.strategies.map((item) => (
              <option key={item.name} value={item.name}>
                {item.name}
                {item.builtin ? ` (${t("nfqws.builtin")})` : ""}
                {item.name === status.active_strategy
                  ? ` — ${t("nfqws.activeStrategy")}`
                  : ""}
              </option>
            ))}
          </select>
          <Button onClick={add} variant="outline">
            <FilePlusIcon />
            {t("nfqws.addStrategy")}
          </Button>
        </div>
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <span className="text-muted-foreground">
            {t("nfqws.activeStrategyLabel")}
          </span>
          {status.active_strategy ? (
            <Badge>{status.active_strategy}</Badge>
          ) : (
            <Badge variant="secondary">{t("nfqws.activeStrategyCustom")}</Badge>
          )}
          {effectiveSelected && effectiveSelected !== status.active_strategy ? (
            <span className="text-muted-foreground">
              {t("nfqws.selectedForEditing", { name: effectiveSelected })}
            </span>
          ) : null}
        </div>
        <CodeEditor
          className="h-[60vh] max-h-[40rem] min-h-[20rem]"
          onChange={(next) =>
            setDraftContent((current) => ({
              ...current,
              [effectiveSelected]: next,
            }))
          }
          syntax={effectiveSelected.endsWith(".list") ? "list" : "nfqws"}
          value={content}
        />
        <div className="flex flex-wrap justify-end gap-2">
          <Button
            disabled={!effectiveSelected}
            onClick={() => void run("apply_strategy")}
          >
            <PlayIcon />
            {t("nfqws.applyStrategy")}
          </Button>
          <Button
            disabled={!effectiveSelected}
            onClick={() => void run("save_strategy")}
            variant="outline"
          >
            <SaveIcon />
            {t("nfqws.saveStrategy")}
          </Button>
          <Button
            disabled={!effectiveSelected}
            onClick={() => {
              if (window.confirm(t("nfqws.confirmDelete")))
                void run("delete_strategy")
            }}
            variant="destructive"
          >
            <TrashIcon />
            {t("common.delete")}
          </Button>
        </div>
      </div>
    </NfqwsSection>
  )
}

function FilesEditor({
  category,
  drafts,
  files,
  onDraftChange,
  onDraftRemove,
  onSaveDrafts,
  refresh,
  readonly = false,
}: {
  category: NfqwsFile["category"]
  drafts: Record<string, DraftFile>
  files: NfqwsFile[]
  onDraftChange: (draft: DraftFile) => void
  onDraftRemove: (category: "list" | "lua", name: string) => void
  onSaveDrafts: (restart: boolean) => Promise<void>
  refresh: () => void
  readonly?: boolean
}) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const available = useMemo(
    () => files.filter((item) => item.category === category),
    [files, category]
  )
  const [selected, setSelected] = useState(available[0]?.name ?? "")
  const current =
    available.find((item) => item.name === selected) ?? available[0]
  const currentKey = current ? `${current.category}/${current.name}` : ""
  const fileQuery = useQuery({
    queryKey: [
      "nfqws",
      "file",
      current?.category,
      current?.name,
      current?.size,
    ],
    queryFn: () => readFile(current!),
    enabled: current !== undefined,
  })
  const content = drafts[currentKey]?.content ?? fileQuery.data?.content ?? ""
  const editableCategory = category === "list" || category === "lua"
  const draftCount = Object.keys(drafts).length
  const create = async () => {
    const stem = window.prompt(t("nfqws.fileName"))
    if (!stem) return
    const extension = category === "lua" ? ".lua" : ".list"
    const name = stem.endsWith(extension) ? stem : stem + extension
    await nfqwsAction({ action: "create_file", category, name, content: "" })
    setSelected(name)
    refresh()
  }
  const remove = async () => {
    if (!current || !window.confirm(t("nfqws.confirmDelete"))) return
    await nfqwsAction({ action: "delete_file", category, name: current.name })
    if (editableCategory) onDraftRemove(category, current.name)
    setSelected("")
    refresh()
  }
  const clearLog = async () => {
    if (!current || !window.confirm(t("nfqws.confirmClearLog"))) return
    await nfqwsAction({ action: "clear_log", name: current.name })
    await queryClient.invalidateQueries({ queryKey: ["nfqws", "file"] })
    toast.success(t("nfqws.logCleared"))
    refresh()
  }
  return (
    <NfqwsSection
      title={t(
        `nfqws.tabs.${category === "list" ? "lists" : category === "lua" ? "lua" : "logs"}`
      )}
    >
      <div className="space-y-4">
        <div className="flex flex-wrap gap-2">
          <select
            className="h-9 min-w-60 rounded-md border bg-background px-3"
            onChange={(event) => setSelected(event.target.value)}
            value={current?.name ?? ""}
          >
            {available.map((file) => (
              <option key={file.name}>{file.name}</option>
            ))}
          </select>
          {!readonly ? (
            <>
              <Button onClick={() => void create()} variant="outline">
                <FilePlusIcon />
                {t("nfqws.newFile")}
              </Button>
              {current?.removable ? (
                <Button onClick={() => void remove()} variant="destructive">
                  <TrashIcon />
                  {t("common.delete")}
                </Button>
              ) : null}
            </>
          ) : null}
          {category === "log" ? (
            <Button onClick={() => void clearLog()} variant="outline">
              <TrashIcon />
              {t("nfqws.clearLog")}
            </Button>
          ) : null}
        </div>
        <CodeEditor
          className="h-[60vh] max-h-[40rem] min-h-[20rem]"
          onChange={(next) => {
            if (current && (category === "list" || category === "lua"))
              onDraftChange({ category, name: current.name, content: next })
          }}
          readOnly={readonly}
          syntax={readonly ? "log" : "nfqws"}
          value={content}
        />
        {!readonly ? (
          <div className="flex flex-wrap items-center justify-end gap-2">
            {draftCount > 0 ? (
              <span className="mr-auto text-sm text-muted-foreground">
                {t("nfqws.draftCount", { count: draftCount })}
              </span>
            ) : null}
            <Button
              disabled={draftCount === 0}
              onClick={() => void onSaveDrafts(false)}
              variant="outline"
            >
              <SaveIcon />
              {t("nfqws.saveDrafts")}
            </Button>
            <Button
              disabled={draftCount === 0}
              onClick={() => void onSaveDrafts(true)}
            >
              <RefreshCwIcon />
              {t("nfqws.saveAndRestart")}
            </Button>
          </div>
        ) : null}
      </div>
    </NfqwsSection>
  )
}

function UrlCheck() {
  const { t } = useTranslation()
  const [url, setUrl] = useState("https://www.youtube.com/")
  const [result, setResult] = useState<boolean | null>(null)
  const check = async () => {
    const response = await nfqwsAction<{ reachable: boolean }>({
      action: "check_url",
      url,
    })
    setResult(response.reachable)
  }
  return (
    <NfqwsSection
      description={t("nfqws.checkDescription")}
      title={t("nfqws.checkTitle")}
    >
      <div className="space-y-4">
        <div className="flex gap-2">
          <Input onChange={(event) => setUrl(event.target.value)} value={url} />
          <Button onClick={() => void check()}>{t("nfqws.check")}</Button>
        </div>
        {result !== null ? (
          // Success in grey read like a note rather than an answer; the whole
          // point of the check is to say yes or no at a glance.
          <Alert
            className={
              result
                ? "border-success/40 bg-success/10 text-success"
                : undefined
            }
            variant={result ? "default" : "destructive"}
          >
            <AlertDescription className={result ? "text-success" : undefined}>
              {result ? t("nfqws.reachable") : t("nfqws.unreachable")}
            </AlertDescription>
          </Alert>
        ) : null}
      </div>
    </NfqwsSection>
  )
}

function NfqwsSection({
  action,
  children,
  className,
  description,
  title,
}: {
  action?: ReactNode
  children: ReactNode
  className?: string
  description?: ReactNode
  title: ReactNode
}) {
  return (
    <section className={cn("space-y-4 py-2", className)}>
      <div className="flex min-w-0 items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 className="text-[20px] leading-7 font-bold text-foreground">
            {title}
          </h2>
          {description ? (
            <div className="mt-1 text-sm leading-[22px] text-muted-foreground">
              {description}
            </div>
          ) : null}
        </div>
        {action ? <div className="shrink-0">{action}</div> : null}
      </div>
      {children}
    </section>
  )
}

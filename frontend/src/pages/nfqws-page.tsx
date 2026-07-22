import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import {
  DownloadIcon,
  FilePlusIcon,
  LoaderCircleIcon,
  PlayIcon,
  RefreshCwIcon,
  RotateCcwIcon,
  SaveIcon,
  TrashIcon,
  UploadIcon,
} from "lucide-react"
import { useEffect, useMemo, useRef, useState } from "react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"

import { PageHeader } from "@/components/shared/page-header"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"
import {
  CardAction,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
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
import { downloadJson, formatDownloadTimestamp } from "@/lib/download"
import {
  createBackup,
  downloadBackup,
  rollbackBackup,
  type BackupSelection,
} from "@/lib/backup"

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
type Tab = "settings" | "strategies" | "lists" | "lua" | "logs" | "check"

type NfqwsActionResult = {
  ok: boolean
  output?: string
  strategy_created?: string
}

type NfqwsUpdateStatus = {
  ok: boolean
  current: string
  latest: string
  available: boolean
  release_url?: string
}

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

async function nfqwsAction<T = NfqwsActionResult>(
  payload: Record<string, unknown>
): Promise<T> {
  const response = await fetch("/api/nfqws", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  })
  const data = await response.json().catch(() => ({}))
  if (!response.ok || data.ok === false)
    throw new Error(
      data.error ??
        data.message ??
        data.output?.trim() ??
        `HTTP ${response.status}`
    )
  return data as T
}

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
  const bundleImportRef = useRef<HTMLInputElement>(null)
  const [bundleExportPending, setBundleExportPending] = useState(false)
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
  const updateQuery = useQuery<NfqwsUpdateStatus>({
    queryKey: ["nfqws", "update"],
    queryFn: () => nfqwsAction({ action: "check_update" }),
    enabled: status?.installed === true,
    retry: false,
    staleTime: 30 * 60 * 1_000,
    refetchInterval: 30 * 60 * 1_000,
    refetchIntervalInBackground: false,
    refetchOnWindowFocus: false,
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
        nfqws: true,
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
        queryClient.setQueryData(["nfqws", "update"], latest)
      } catch {
        await queryClient.invalidateQueries({ queryKey: ["nfqws", "update"] })
      }
    }
  }

  const refreshAll = async () => {
    await query.refetch()
    if (!status?.installed) return
    try {
      const latest = await nfqwsAction<NfqwsUpdateStatus>({
        action: "check_update",
        force: true,
      })
      queryClient.setQueryData(["nfqws", "update"], latest)
    } catch {
      await queryClient.invalidateQueries({ queryKey: ["nfqws", "update"] })
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
  const bundleMutation = useMutation({
    mutationFn: async (file: File) => {
      const parsed = JSON.parse(await file.text()) as {
        format?: string
        version?: number
        files?: Record<string, unknown>
      }
      if (
        parsed.format !== "keen-pbr-sb-nfqws" ||
        parsed.version !== 1 ||
        !parsed.files
      ) {
        throw new Error(t("configTransfer.invalidFormat"))
      }
      await nfqwsAction({ action: "import_bundle", files: parsed.files })
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["nfqws"] })
      toast.success(t("configTransfer.imported"))
    },
    onError: (error) =>
      toast.error(
        error instanceof Error
          ? error.message
          : t("configTransfer.invalidFormat"),
        { richColors: true }
      ),
    onSettled: () => {
      if (bundleImportRef.current) bundleImportRef.current.value = ""
    },
  })

  const exportBundle = async () => {
    if (!status) return
    setBundleExportPending(true)
    try {
      const files: Record<"config" | "list", Record<string, string>> = {
        config: {},
        list: {},
      }
      for (const file of status.files) {
        if (file.category !== "config" && file.category !== "list") continue
        files[file.category][file.name] = (await readFile(file)).content
      }
      downloadJson(`keen-pbr-sb-nfqws-${formatDownloadTimestamp()}.json`, {
        format: "keen-pbr-sb-nfqws",
        version: 1,
        files,
      })
    } catch (error) {
      toast.error(
        error instanceof Error
          ? error.message
          : t("configTransfer.exportFailed"),
        { richColors: true }
      )
    } finally {
      setBundleExportPending(false)
    }
  }

  return (
    <div className="space-y-3">
      <PageHeader
        actions={
          <div className="flex flex-wrap gap-2">
            <Button
              disabled={
                !status?.installed ||
                bundleMutation.isPending ||
                bundleExportPending
              }
              onClick={() => void exportBundle()}
              variant="outline"
            >
              <DownloadIcon />
              {t("configTransfer.exportAll")}
            </Button>
            <Button
              disabled={
                !status?.installed ||
                bundleMutation.isPending ||
                bundleExportPending
              }
              onClick={() => bundleImportRef.current?.click()}
              variant="outline"
            >
              <UploadIcon />
              {t("configTransfer.importAll")}
            </Button>
            <input
              accept="application/json,.json"
              className="hidden"
              onChange={(event) => {
                const file = event.target.files?.[0]
                if (file) bundleMutation.mutate(file)
              }}
              ref={bundleImportRef}
              type="file"
            />
            <Button
              disabled={query.isFetching || updateQuery.isFetching}
              onClick={() => void refreshAll()}
              variant="outline"
            >
              <RefreshCwIcon
                className={
                  query.isFetching || updateQuery.isFetching
                    ? "animate-spin"
                    : ""
                }
              />
              {t("nfqws.refresh")}
            </Button>
          </div>
        }
        description={t("nfqws.description")}
        title="nfqws2"
      />

      {!status?.installed && !query.isLoading ? <NotInstalled /> : null}

      {status?.installed ? (
        <>
          <Card
            className={
              updateQuery.data?.available
                ? "border-emerald-500/70 bg-emerald-500/[0.06] shadow-[0_0_0_1px_rgb(16_185_129/0.12)]"
                : undefined
            }
          >
            <CardHeader>
              <CardTitle>{t("nfqws.service")}</CardTitle>
              <CardDescription>
                {t("nfqws.version", { version: status.version || "—" })}
                {updateQuery.data?.available ? (
                  <span className="mt-1 block font-medium text-emerald-700 dark:text-emerald-400">
                    {t("nfqws.updateAvailable", {
                      version: updateQuery.data.latest,
                    })}
                  </span>
                ) : null}
              </CardDescription>
              <CardAction>
                <Badge
                  size="xs"
                  variant={status.running ? "success" : "secondary"}
                >
                  <span className="mr-1.5 size-1.5 rounded-full bg-current" />
                  {status.running ? t("nfqws.running") : t("nfqws.stopped")}
                </Badge>
              </CardAction>
            </CardHeader>
            <CardContent className="flex flex-wrap items-center justify-between gap-2">
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
            </CardContent>
          </Card>

          <div className="flex flex-wrap gap-x-1 border-b">
            {(
              [
                "settings",
                "strategies",
                "lists",
                "lua",
                "logs",
                "check",
              ] as Tab[]
            ).map((value) => (
              <Button
                key={value}
                className={
                  tab === value
                    ? "rounded-none border-x-0 border-t-0 border-b-2 border-primary bg-transparent px-4 text-foreground shadow-none hover:bg-transparent"
                    : "rounded-none border-0 border-b-2 border-transparent bg-transparent px-4 text-muted-foreground shadow-none hover:bg-muted/50 hover:text-foreground"
                }
                onClick={() => setTab(value)}
                size="default"
                variant="ghost"
              >
                {t(`nfqws.tabs.${value}`)}
              </Button>
            ))}
          </div>

          {tab === "settings" ? (
            <SettingsEditor
              status={status}
              refresh={() => void query.refetch()}
            />
          ) : null}
          {tab === "strategies" ? (
            <StrategiesEditor
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
  status,
  refresh,
}: {
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
  useEffect(() => {
    if (fileName)
      void nfqwsAction<{ content: string }>({
        action: "read_file",
        category: "config",
        name: fileName,
      }).then(({ content }) => {
        setSource(content)
        setForm(parseNfqwsConfig(content))
      })
  }, [fileName])
  const save = async () => {
    if (!file || !form) return
    await nfqwsAction({
      action: "save_file",
      category: "config",
      name: file.name,
      content: formatNfqwsConfig(source, form),
    })
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
    <Card>
      <CardHeader>
        <CardTitle>{t("nfqws.settingsTitle")}</CardTitle>
        <CardDescription>{t("nfqws.settingsDescription")}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
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
      </CardContent>
    </Card>
  )
}

function StrategiesEditor({
  refresh,
  runOperation,
  status,
}: {
  refresh: () => void
  runOperation: RunOperation
  status: Status
}) {
  const { t } = useTranslation()
  const preferredStrategy =
    status.active_strategy || status.strategies[0]?.name || ""
  const [selected, setSelected] = useState(preferredStrategy)
  const [draftContent, setDraftContent] = useState<Record<string, string>>({})
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
      toast.success(t("nfqws.saved"))
      refresh()
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      toast.error(message, { richColors: true })
    }
  }
  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("nfqws.strategiesTitle")}</CardTitle>
        <CardDescription>{t("nfqws.strategiesDescription")}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
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
      </CardContent>
    </Card>
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
    <Card>
      <CardHeader>
        <CardTitle>
          {t(
            `nfqws.tabs.${category === "list" ? "lists" : category === "lua" ? "lua" : "logs"}`
          )}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
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
      </CardContent>
    </Card>
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
    <Card>
      <CardHeader>
        <CardTitle>{t("nfqws.checkTitle")}</CardTitle>
        <CardDescription>{t("nfqws.checkDescription")}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
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
      </CardContent>
    </Card>
  )
}

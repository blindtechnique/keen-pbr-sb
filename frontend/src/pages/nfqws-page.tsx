import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import {
  ArchiveIcon,
  BookmarkIcon,
  ChevronDownIcon,
  ChevronRightIcon,
  DownloadIcon,
  EraserIcon,
  ExternalLinkIcon,
  FileCogIcon,
  FilePlusIcon,
  LoaderCircleIcon,
  PlayIcon,
  PowerIcon,
  RefreshCwIcon,
  RotateCcwIcon,
  SaveIcon,
  UploadIcon,
  WrenchIcon,
} from "lucide-react"
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react"

import {
  subscribeComponentTransaction,
  type ComponentTransactionProgress,
} from "@/api/component-transaction-events"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"

import { KeenPencilIcon, KeenTrashIcon } from "@/components/shared/keen-icons"
import { NfqwsProfileCards } from "@/components/nfqws/profile-cards"
import { StrategyBreakdown } from "@/components/nfqws/strategy-breakdown"
import { DataTable } from "@/components/shared/data-table"
import { ListPlaceholder } from "@/components/shared/list-placeholder"
import { PageActionBar } from "@/components/shared/page-action-bar"
import { PageHeader } from "@/components/shared/page-header"
import { HelpHint } from "@/components/shared/help-hint"
import { SectionHeading } from "@/components/shared/section-heading"
import { SegmentedControl } from "@/components/shared/segmented-control"
import { TableSkeleton } from "@/components/shared/table-skeleton"
import { Skeleton } from "@/components/ui/skeleton"
import { KeeneticStatus } from "@/components/shared/keenetic-status"
import { SectionTabs, type SectionTab } from "@/components/shared/section-tabs"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"

const MODE_OPTIONS = ["MODE_AUTO", "MODE_LIST", "MODE_ALL"] as const

import { Switch } from "@/components/ui/switch"
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"
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
  type BackupSelection,
} from "@/lib/backup"
import {
  NFQWS_UPDATE_QUERY_KEY,
  classifyNfqwsUpdateNotice,
  nfqwsAction,
  nfqwsUpdateQueryOptions,
  type NfqwsActionResult,
  type NfqwsRotatorState,
  type NfqwsUpdateStatus,
} from "@/api/nfqws"
import { copyText } from "@/lib/clipboard"
import { cn } from "@/lib/utils"
import {
  nfqwsUpgradeBlockKind,
  nfqwsUpgradeAllowed,
  nfqwsUpgradeButton,
  type NfqwsUpgradeCapability,
} from "@/lib/nfqws-upgrade-capability"
import {
  canonicalNfqwsProfileTier,
  nfqwsProfileMatchesPackage,
  NFQWS_PROFILE_ORDER,
  nfqwsBuiltinStrategyDisplayKey,
  parseNfqwsProfileMarker,
} from "@/pages/nfqws-strategy-model"

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
  // Optional so a page talking to an older backend degrades to the marker
  // rule rather than dropping every bundled profile out of the cards.
  canonical?: boolean
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
  rotator_state: NfqwsRotatorState
  // Optional so a page talking to an older backend degrades to "nothing to
  // say" rather than to a confident wrong answer.
  transaction_state?: string
  restore_point?: string
  upgrade_capability?: NfqwsUpgradeCapability
  restore_capability?: {
    available: boolean
    exact_package_state: boolean
    limitation: string
  }
}
// «Стратегии» первыми и по умолчанию: на эту страницу приходят выбрать или
// переключить стратегию, а «Настройки» — редкий и куда более технический
// экран, туда же уехала строка запуска. Открывать страницу на нём значило
// встречать человека тем, зачем он почти никогда не приходил.
// «Списки» и «Lua-скрипты» — это один и тот же экран правки файла на диске,
// и оба нужны редко. Вместе они занимали две вкладки из шести, а «Списки»
// вдобавок повторяли название пункта меню, за которым лежат совсем другие
// списки keen-pbr. Теперь это «Файлы» с переключателем внутри.
const NFQWS_TAB_VALUES = ["strategies", "settings", "files", "logs"] as const

type Tab = (typeof NFQWS_TAB_VALUES)[number]

type OperationState = {
  open: boolean
  pending: boolean
  success?: boolean
  title: string
  output: string
}

type DraftFile = {
  category: "list" | "lua"
  name: string
  content: string
}

type RunOperation = (
  title: string,
  operation: () => Promise<NfqwsActionResult>,
  successMessage: string
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
  const upgradeBlockedDescription =
    nfqwsUpgradeBlockKind(status?.upgrade_capability) === "metadata_unverified"
      ? t("nfqws.upgradeMetadataUnverifiedDescription")
      : t("nfqws.upgradeUnavailableDescription")
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
  const [tab, setTab] = useState<Tab>("strategies")
  // Какой из двух файловых редакторов открыт внутри вкладки «Файлы».
  const [filesCategory, setFilesCategory] = useState<"list" | "lua">("list")
  const [upgradeOpen, setUpgradeOpen] = useState(false)
  const [installOpen, setInstallOpen] = useState(false)
  const [restoreOpen, setRestoreOpen] = useState(false)
  const [downloadUpgradeBackup, setDownloadUpgradeBackup] = useState(true)
  const [drafts, setDrafts] = useState<Record<string, DraftFile>>({})
  const [operation, setOperation] = useState<OperationState>({
    open: false,
    pending: false,
    title: "",
    output: "",
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
  // Одно решение на кнопку, посчитанное там же, где живут остальные правила
  // обновления. Страница только рисует то, что ей сказали.
  const upgradeButton = nfqwsUpgradeButton(
    updateQuery.data,
    status?.upgrade_capability,
    operation.pending,
    updateQuery.isFetching
  )

  const runOperation: RunOperation = async (title, execute, successMessage) => {
    setOperation({
      open: true,
      pending: true,
      title,
      output: t("nfqws.operationRunning"),
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
      })
      return false
    }
  }

  const runUpgrade = async () => {
    setUpgradeOpen(false)
    if (!nfqwsUpgradeAllowed(status?.upgrade_capability)) {
      toast.error(upgradeBlockedDescription, {
        richColors: true,
      })
      return
    }
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
        })
        return
      }
    }
    const completed = await runOperation(
      t("nfqws.upgrade"),
      () => nfqwsAction({ action: "upgrade" }),
      t("nfqws.operationCompleted")
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

  const runInstall = async () => {
    setInstallOpen(false)
    await runOperation(
      t("nfqws.install"),
      () => nfqwsAction({ action: "install" }),
      t("nfqws.operationCompleted")
    )
    // Success or failure, the page's idea of "installed" may have changed;
    // runOperation already invalidated the status query.
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
      const notice = classifyNfqwsUpdateNotice(latest)
      if (notice === "degraded") {
        toast.warning(t("nfqws.updateStateUnverified"), {
          richColors: true,
        })
      } else if (notice === "available") {
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
      {/* Действия страницы уехали в раздел «Служба»: это единственная страница,
          где кнопки жили в заголовке, и «Резервные копии» с «Обновить»
          относятся к службе, а не к таблице под вкладками. Заголовок теперь
          такой же, как у всех остальных страниц. */}
      <PageHeader
        description={t("nfqws.description")}
        // The heading is a link, so the tab text is given explicitly.
        documentTitle="nfqws2"
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
      <input
        accept="application/json,.json"
        className="hidden"
        onChange={(event) => void restoreBackup(event.target.files?.[0])}
        ref={backupImportRef}
        type="file"
      />

      {query.isLoading ? <TableSkeleton /> : null}

      {!status?.installed && !query.isLoading ? (
        <NotInstalled
          installBlocked={
            status !== undefined &&
            status.transaction_state !== undefined &&
            status.transaction_state !== "none"
          }
          onInstall={() => setInstallOpen(true)}
        />
      ) : null}

      {status?.installed ? (
        <>
          <NfqwsSection
            title={
              // Знак вопроса у названия раздела — приём KeeneticOS: объяснение
              // под рукой, но не занимает экран у того, кто и так знает. По
              // подписям не видно, чем «Перезапустить» отличается от
              // «Перечитать конфигурацию», а «Обновить данные» — от «Обновить
              // пакет», и держать это в голове человек не обязан.
              <span className="inline-flex flex-wrap items-center gap-1">
                {t("nfqws.service")}
                <HelpHint
                  label={t("nfqws.serviceHelp.label")}
                  text={<ServiceActionsHelp />}
                />
              </span>
            }
            // Версия и обе плашки — одной строкой под заголовком. Раньше
            // версия стояла слева, а плашки уезжали в правый угол секции, и
            // одно состояние службы читалось по разным углам экрана.
            description={
              <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
                <span>
                  {t("nfqws.version", { version: status.version || "—" })}
                </span>
                <KeeneticStatus tone={status.running ? "success" : "neutral"}>
                  {status.running ? t("nfqws.running") : t("nfqws.stopped")}
                </KeeneticStatus>
                <KeeneticStatus
                  tone={updateQuery.data?.available ? "success" : "neutral"}
                >
                  {updateQuery.data?.available
                    ? t("common.updateStatus.available")
                    : updateQuery.data
                      ? t("common.updateStatus.current")
                      : t("common.updateStatus.checking")}
                </KeeneticStatus>
              </span>
            }
          >
            {/* Выключатель и три кнопки — одной строкой слева. Пока кнопок
                было семь, ряд разводился `justify-between`; с тремя это
                оставляло посреди блока пустоту в пол-экрана. */}
            <div className="flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-center sm:gap-3">
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
              {/* На телефоне — сетка в две равные колонки, как в панели действий
                  на остальных страницах. В обычном `flex-wrap` каждая кнопка
                  занимала ширину своей подписи, и пять кнопок вставали лесенкой
                  2 + 2 + 1 разной длины.

                  Подписи стали длиннее («Перезапустить службу» вместо
                  «Перезапустить»), и в половину телефонного экрана они больше
                  не влезают: у кнопок базовый `whitespace-nowrap` и жёсткая
                  высота, поэтому текст вылезал за рамку на соседнюю кнопку.
                  На узком экране разрешаем перенос и высоту по содержимому —
                  с `items-stretch` кнопки в ряду всё равно одной высоты. */}
              {/* A package operation that never reported an end. Shown here
                  and not only when the next upgrade refuses: a reboot in the
                  middle of one leaves this record, and the moment to learn
                  about it is before deciding what to do next. */}
              {status?.transaction_state === "abandoned" ||
              status?.transaction_state === "unreadable" ? (
                <Alert variant="destructive">
                  <AlertTitle>
                    {t("nfqws.interruptedTransactionTitle")}
                  </AlertTitle>
                  <AlertDescription>
                    {t("nfqws.interruptedTransactionDescription")}
                    {/* The daemon already looked at this journal at boot -
                        the backend only publishes the record when it talks
                        about this very journal. Without this line "did not
                        finish" reads as "nobody did anything"; the wording
                        must still not overclaim, so a failed recovery says
                        failed, not "kept on purpose". */}
                    {status.upgrade_capability?.boot_recovery_last ? (
                      <>
                        {" "}
                        {t(
                          status.upgrade_capability.boot_recovery_last
                            .outcome === "failed"
                            ? "nfqws.bootRecoveryFailed"
                            : "nfqws.bootRecoveryRan",
                          {
                            plan: status.upgrade_capability.boot_recovery_last
                              .plan,
                            outcome:
                              status.upgrade_capability.boot_recovery_last
                                .outcome,
                          },
                        )}
                      </>
                    ) : null}
                  </AlertDescription>
                </Alert>
              ) : null}
              {status.upgrade_capability?.available === false ? (
                <Alert>
                  <AlertTitle>{t("nfqws.upgradeUnavailableTitle")}</AlertTitle>
                  <AlertDescription>
                    {upgradeBlockedDescription}
                  </AlertDescription>
                </Alert>
              ) : null}
              {/* Ежедневных действий здесь два: перезапустить службу и
                  перечитать состояние. Остальные пять — про обслуживание
                  пакета и про то, как вернуться назад; они редкие и лежат
                  под одной кнопкой. Семь равнозначных кнопок в два ряда
                  занимали 190 px на широком экране и 358 px на телефоне
                  раньше, чем начиналось содержимое, и не давали понять, что
                  из этого делают каждый день. */}
              <div className="grid grid-cols-2 items-stretch gap-2 *:h-auto *:min-h-8 *:w-full *:py-1 *:leading-tight *:whitespace-normal sm:flex sm:flex-wrap sm:items-center sm:*:h-8 sm:*:w-auto sm:*:py-0 sm:*:whitespace-nowrap">
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
                  title={t("nfqws.serviceHelp.restart")}
                  variant="outline"
                >
                  {/* Перезапуск — это выключение и включение службы, отсюда
                      знак питания. С RefreshCwIcon он был неотличим от
                      «Обновить данные». */}
                  <PowerIcon />
                  {t("nfqws.restart")}
                </Button>
                <Button
                  disabled={
                    query.isFetching || updateQuery.isFetching || refreshPending
                  }
                  onClick={() => void refreshAll()}
                  title={t("nfqws.serviceHelp.refresh")}
                  variant="outline"
                >
                  <RefreshCwIcon
                    className={
                      query.isFetching ||
                      updateQuery.isFetching ||
                      refreshPending
                        ? "animate-spin"
                        : ""
                    }
                  />
                  {t("nfqws.refresh")}
                </Button>
                {/* Обновление уехало из «Обслуживания» на видное место: это не
                    редкое действие, а то, ради чего страницу и открывают,
                    когда вышла новая версия. Логика — та же, что у кнопки
                    sing-box: кнопка не исчезает, когда обновлять нечего, а
                    гаснет и подсказкой говорит, почему. */}
                <Tooltip>
                  <TooltipTrigger
                    render={
                      <span className="flex py-0! sm:inline-flex">
                        {/* Обёртка нужна: выключенная кнопка не шлёт события
                            мыши, а подсказка на выключенной кнопке — ровно
                            та, которая оператору нужнее всего.

                            Но обёртка не должна менять размер кнопки, а она
                            меняла — потому что размеры этому ряду раздаются
                            через `*:`, а `*:` достаётся только прямым детям.
                            Прямой ребёнок здесь — обёртка, и весь рецепт
                            (`h-auto min-h-8 py-1 leading-tight
                            whitespace-normal`) оседал на ней, пока кнопка
                            внутри оставалась с жёстким `h-8`. Поэтому рецепт
                            повторён на самой кнопке, а обёртке отменён
                            вертикальный отступ — её `py-1` лежал бы снаружи
                            рамки кнопки и сдвигал бы её от края ячейки.

                            `leading-tight` здесь не лишний: кнопка объявляет
                            свою `line-height` через `text-sm`, и объявление
                            бьёт унаследованное. Уберёте — двухстрочная
                            подпись станет выше соседних. */}
                        <Button
                          className="h-auto min-h-8 w-full py-1 leading-tight whitespace-normal sm:h-8 sm:w-auto sm:py-0 sm:whitespace-nowrap"
                          disabled={!upgradeButton.enabled}
                          onClick={() => setUpgradeOpen(true)}
                          variant="outline"
                        >
                          <DownloadIcon />
                          {t("nfqws.upgrade")}
                        </Button>
                      </span>
                    }
                  />
                  <TooltipContent>{t(upgradeButton.tooltipKey)}</TooltipContent>
                </Tooltip>
                <NfqwsMaintenanceMenu
                  items={[
                    {
                      key: "reload",
                      icon: FileCogIcon,
                      label: t("nfqws.reload"),
                      hint: t("nfqws.serviceHelp.reload"),
                      disabled: operation.pending,
                      onSelect: () =>
                        void runOperation(
                          t("nfqws.reload"),
                          () =>
                            nfqwsAction({
                              action: "service",
                              command: "reload",
                            }),
                          t("nfqws.operationCompleted")
                        ),
                    },
                    {
                      key: "captureRestorePoint",
                      icon: BookmarkIcon,
                      label: t("nfqws.captureRestorePoint"),
                      hint: t("nfqws.serviceHelp.captureRestorePoint"),
                      disabled: operation.pending || !status?.installed,
                      onSelect: () =>
                        void runOperation(
                          t("nfqws.captureRestorePoint"),
                          () =>
                            nfqwsAction({ action: "capture_restore_point" }),
                          t("nfqws.operationCompleted")
                        ),
                    },
                    {
                      key: "restoreComponent",
                      icon: RotateCcwIcon,
                      label: t("nfqws.restoreComponent"),
                      hint: t("nfqws.serviceHelp.restoreComponent"),
                      disabled:
                        operation.pending ||
                        !status?.installed ||
                        status?.restore_point !== "usable",
                      disabledReason:
                        status?.restore_point === "usable"
                          ? undefined
                          : t("nfqws.restorePointMissing"),
                      onSelect: () => setRestoreOpen(true),
                    },
                    {
                      key: "backup",
                      icon: ArchiveIcon,
                      label: t("nfqws.backup.button"),
                      hint: t("nfqws.serviceHelp.backup"),
                      disabled: !status?.installed || backupPending !== null,
                      onSelect: () => setBackupOpen(true),
                    },
                  ]}
                />
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
          {tab === "files" ? (
            <div className="space-y-3">
              {/* Переключатель из двух пунктов на всю ширину экрана выглядел
                  бы важнее самого содержимого — держим его в ширину поля. */}
              <SegmentedControl
                className="max-w-[480px]"
                ariaLabel={t("nfqws.tabs.files")}
                onChange={setFilesCategory}
                options={[
                  { value: "list", label: t("nfqws.tabs.lists") },
                  { value: "lua", label: t("nfqws.tabs.lua") },
                ]}
                value={filesCategory}
              />
              <FilesEditor
                category={filesCategory}
                drafts={drafts}
                files={status.files}
                key={filesCategory}
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
            </div>
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
          <NfqwsUpgradeDialog
            capability={status.upgrade_capability}
            downloadBackup={downloadUpgradeBackup}
            latest={updateQuery.data?.latest}
            onDownloadBackupChange={setDownloadUpgradeBackup}
            onOpenChange={setUpgradeOpen}
            onUpgrade={() => void runUpgrade()}
            open={upgradeOpen}
          />
          <NfqwsRestoreComponentDialog
            onOpenChange={setRestoreOpen}
            onRestore={() => {
              setRestoreOpen(false)
              void runOperation(
                t("nfqws.restoreComponent"),
                () => nfqwsAction({ action: "restore_component" }),
                t("nfqws.operationCompleted")
              )
            }}
            open={restoreOpen}
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
      {/* Outside the installed-only branch on purpose: the install runs
          exactly when nothing is installed, and its progress/result dialog
          must render then too. */}
      <NfqwsOperationDialog
        onClose={() =>
          setOperation((current) => ({ ...current, open: false }))
        }
        operation={operation}
      />
      <NfqwsConfirmDialog
        confirmLabel={t("nfqws.install")}
        description={t("nfqws.installConfirmDescription")}
        destructive={false}
        onConfirm={() => void runInstall()}
        onOpenChange={setInstallOpen}
        open={installOpen}
        title={t("nfqws.installConfirmTitle")}
      />
    </div>
  )
}

// Step names the backend can send, mapped to the text an operator reads. A
// name missing here shows nothing rather than a guess, which is why the map is
// exhaustive over the handler's steps and asserted by a test.
const progressStepKeys: Record<string, string> = {
  backup: "progressStepBackup",
  capture: "progressStepCapture",
  install: "progressStepInstall",
  verify: "progressStepVerify",
  rollback: "progressStepRollback",
  stop: "progressStepStop",
  restore: "progressStepRestore",
  start: "progressStepStart",
}

function useComponentTransactionProgress() {
  const [progress, setProgress] = useState<ComponentTransactionProgress | null>(
    null
  )
  useEffect(() => subscribeComponentTransaction(setProgress), [])
  return progress
}

function NfqwsOperationDialog({
  onClose,
  operation,
}: {
  onClose: () => void
  operation: OperationState
}) {
  const { t } = useTranslation()
  // Progress arrives on the shared status stream, not in the response to the
  // request that is still running. Unknown step names fall back to the plain
  // "running" text rather than being printed raw: a backend step this page has
  // never heard of is not something to show an operator as an explanation.
  const progress = useComponentTransactionProgress()
  const progressStep =
    operation.pending && progress && progressStepKeys[progress.step]
      ? t(`nfqws.${progressStepKeys[progress.step]}`)
      : ""
  return (
    <Dialog
      onOpenChange={(open) => {
        if (!open && !operation.pending) onClose()
      }}
      open={operation.open}
    >
      <DialogContent
        className="overflow-hidden sm:max-w-xl"
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
              ? progressStep
                ? t("nfqws.operationRunningStep", { step: progressStep })
                : t("nfqws.operationRunning")
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
        className="overflow-hidden max-sm:top-auto max-sm:bottom-0 max-sm:left-0 max-sm:max-h-[calc(100dvh-0.75rem)] max-sm:max-w-none max-sm:translate-x-0 max-sm:translate-y-0 max-sm:rounded-b-none max-sm:border-x-0 max-sm:border-b-0 sm:max-w-[640px]"
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
  capability,
  downloadBackup,
  latest,
  onDownloadBackupChange,
  onOpenChange,
  onUpgrade,
  open,
}: {
  capability?: NfqwsUpgradeCapability
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
        {capability?.mode === "guarded_opkg" ? (
          <Alert variant="destructive">
            <AlertTitle>{t("nfqws.upgradeGuardedTitle")}</AlertTitle>
            <AlertDescription>
              {t("nfqws.upgradeGuardedDescription")}
            </AlertDescription>
          </Alert>
        ) : null}
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

// Confirmation, not a plain button. This replaces installed binaries with
// older ones and restarts the component; it is the same class of action as the
// upgrade and gets the same pause before it happens.
function NfqwsRestoreComponentDialog({
  onOpenChange,
  onRestore,
  open,
}: {
  onOpenChange: (open: boolean) => void
  onRestore: () => void
  open: boolean
}) {
  const { t } = useTranslation()
  return (
    <Dialog onOpenChange={onOpenChange} open={open}>
      <DialogContent showCloseButton={false}>
        <DialogHeader>
          <DialogTitle>{t("nfqws.restoreComponentConfirmTitle")}</DialogTitle>
          <DialogDescription>
            {t("nfqws.restoreComponentConfirmDescription")}
          </DialogDescription>
        </DialogHeader>
        <Alert>
          <AlertTitle>{t("nfqws.restoreComponentLimitTitle")}</AlertTitle>
          <AlertDescription>
            {t("nfqws.restoreComponentLimitDescription")}
          </AlertDescription>
        </Alert>
        <DialogFooter>
          <Button onClick={() => onOpenChange(false)} variant="outline">
            {t("common.cancel")}
          </Button>
          <Button onClick={onRestore} variant="destructive">
            <RotateCcwIcon />
            {t("nfqws.restoreComponent")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function NotInstalled({
  installBlocked,
  onInstall,
}: {
  /** Незавершённая транзакция пакета: установка откажет с 409, поэтому
      кнопка честно выключена, а не даёт нажать и упасть. */
  installBlocked: boolean
  onInstall: () => void
}) {
  const { t } = useTranslation()
  return (
    <Alert variant="destructive">
      <AlertTitle>{t("nfqws.notInstalled.title")}</AlertTitle>
      <AlertDescription className="space-y-3">
        <p>{t("nfqws.notInstalled.description")}</p>
        <div className="space-y-1">
          <Button
            className="w-full sm:w-auto"
            disabled={installBlocked}
            onClick={onInstall}
          >
            {t("nfqws.install")}
          </Button>
          <p className="text-xs">
            {installBlocked
              ? t("nfqws.installBlockedByTransaction")
              : t("nfqws.installHint")}
          </p>
        </div>
        <div>
          <p className="mb-1 font-medium">
            {t("nfqws.notInstalled.ourInstaller")}
          </p>
          <code className="block rounded bg-muted p-2 text-xs break-all text-foreground">
            sh -c &quot;$(curl -fsSL
            https://raw.githubusercontent.com/blindtechnique/keen-pbr-sb/main/install.sh)&quot;
          </code>
        </div>
        <div>
          <p className="mb-1 font-medium">{t("nfqws.notInstalled.original")}</p>
          <code className="block rounded bg-muted p-2 text-xs break-all text-foreground">
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
  // Форма ещё грузится — это не «файла нет». Раньше обе ситуации показывали
  // одну и ту же красную мысль «nfqws2.conf не найден», и она мигала при
  // каждом нормальном открытии вкладки.
  if (file && !form) return <TableSkeleton />
  if (!file)
    return (
      <Alert>
        <AlertDescription>{t("nfqws.configMissing")}</AlertDescription>
      </Alert>
    )

  const settingsForm: NfqwsConfigForm = form as NfqwsConfigForm
  const field = (key: keyof NfqwsConfigForm) => (
    <NfqwsField
      key={key}
      onChange={(next) => setForm({ ...settingsForm, [key]: next })}
      variable={key}
      value={String(settingsForm[key])}
    />
  )
  const toggle = (key: "IPV6_ENABLED" | "POLICY_EXCLUDE" | "LOG_LEVEL") => (
    <label
      className="flex min-h-10 max-w-[480px] cursor-pointer items-start gap-3 py-1"
      key={key}
    >
      <Checkbox
        checked={settingsForm[key]}
        className="mt-0.5"
        onCheckedChange={(checked) =>
          setForm({ ...settingsForm, [key]: checked === true })
        }
      />
      <span className="min-w-0">
        <span className="block text-sm">{t(`nfqws.fields.${key}.label`)}</span>
        <span className="block text-xs text-muted-foreground">
          {t(`nfqws.fields.${key}.hint`)}
        </span>
      </span>
    </label>
  )

  return (
    <div className="space-y-6">
      <SectionHeading
        description={t("nfqws.settingsDescription")}
        title={t("nfqws.settingsTitle")}
      />

      {/* Настройки разложены по смыслу, а не в порядке строк в файле: сначала
          «где применять», потом «как обходить», потом «прочее». Подписи — по-
          человечески; имя переменной осталось мелкой моноширинной пометкой,
          чтобы тот, кто пришёл из nfqws2.conf, нашёл знакомое. */}
      <div className="space-y-4">
        <SectionHeading
          description={t("nfqws.groups.scopeDescription")}
          size="compact"
          title={t("nfqws.groups.scope")}
        />
        {field("ISP_INTERFACE")}
        {field("TCP_PORTS")}
        {field("UDP_PORTS")}
        {field("POLICY_NAME")}
        {toggle("POLICY_EXCLUDE")}
        {toggle("IPV6_ENABLED")}
      </div>

      <div className="space-y-4">
        <SectionHeading
          description={t("nfqws.groups.bypassDescription")}
          size="compact"
          title={t("nfqws.groups.bypass")}
        />
        <div className="grid max-w-[480px] gap-1.5">
          <Label>{t("nfqws.fields.NFQWS_EXTRA_ARGS.label")}</Label>
          <Select
            items={MODE_OPTIONS.map((mode) => ({
              value: mode,
              label: t(`nfqws.modes.${mode}`),
            }))}
            onValueChange={(value) =>
              setForm({
                ...settingsForm,
                NFQWS_EXTRA_ARGS: (value ??
                  settingsForm.NFQWS_EXTRA_ARGS) as NfqwsConfigForm["NFQWS_EXTRA_ARGS"],
              })
            }
            value={settingsForm.NFQWS_EXTRA_ARGS}
          >
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                {MODE_OPTIONS.map((mode) => (
                  <SelectItem key={mode} value={mode}>
                    {t(`nfqws.modes.${mode}`)}
                  </SelectItem>
                ))}
              </SelectGroup>
            </SelectContent>
          </Select>
          <p className="text-xs text-muted-foreground">
            {t("nfqws.fields.NFQWS_EXTRA_ARGS.hint")}
          </p>
        </div>
        {field("NFQWS_BASE_ARGS")}
        {field("NFQWS_ARGS")}
        {field("NFQWS_ARGS_QUIC")}
        {field("NFQWS_ARGS_UDP")}
        {field("NFQWS_ARGS_CUSTOM")}
        {field("NFQWS_ARGS_IPSET")}
      </div>

      <div className="space-y-4">
        <SectionHeading
          description={t("nfqws.groups.otherDescription")}
          size="compact"
          title={t("nfqws.groups.other")}
        />
        {toggle("LOG_LEVEL")}
      </div>

      <div className="flex justify-end">
        <Button onClick={() => void save()}>
          <SaveIcon />
          {t("nfqws.save")}
        </Button>
      </div>
    </div>
  )
}

/**
 * Одно поле настроек nfqws2.
 *
 * Подпись человеческая, под ней объяснение, а исходное имя переменной стоит
 * рядом мелким моноширинным шрифтом. Раньше подписью было само имя —
 * `NFQWS_ARGS_QUIC`, — и человеку, который открыл эту страницу впервые,
 * оставалось гадать, что туда писать.
 */
function NfqwsField({
  onChange,
  value,
  variable,
}: {
  onChange: (next: string) => void
  value: string
  variable: keyof NfqwsConfigForm
}) {
  const { t } = useTranslation()

  if (String(variable).includes("ARGS")) {
    return (
      <ArgsField
        // Ключ подсказки записан буквально, а не собран из имени переменной:
        // пояснение есть пока только у базовых аргументов, а шаблонная строка
        // потребовала бы объявлять целое семейство ключей ради одного.
        help={
          variable === "NFQWS_BASE_ARGS"
            ? t("nfqws.fields.NFQWS_BASE_ARGS.help")
            : undefined
        }
        hint={t(`nfqws.fields.${variable}.hint`)}
        label={t(`nfqws.fields.${variable}.label`)}
        onChange={onChange}
        value={value}
        variable={variable}
      />
    )
  }

  return (
    <div className="grid max-w-[480px] gap-1.5">
      <Label className="flex flex-wrap items-baseline gap-2">
        {t(`nfqws.fields.${variable}.label`)}
        <span className="font-mono text-[11px] font-normal text-muted-foreground">
          {variable}
        </span>
      </Label>
      <Input
        className="font-mono"
        onChange={(event) => onChange(event.target.value)}
        value={value}
      />
      <p className="text-xs text-muted-foreground">
        {t(`nfqws.fields.${variable}.hint`)}
      </p>
    </div>
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
  const queryClient = useQueryClient()
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
  // «Применена» — только когда применён именно этот текст. Правки снимают
  // запрет: иначе применить их было бы нечем. Без этого кнопка оставалась
  // активной у уже применённой стратегии, и второе нажатие перезапускало
  // службу впустую.
  const selectedHasEdits =
    draftContent[effectiveSelected] !== undefined &&
    draftContent[effectiveSelected] !== strategy?.content
  const selectedIsApplied =
    effectiveSelected === status.active_strategy && !selectedHasEdits
  const [editorViewChoice, setEditorViewChoice] = useState<"breakdown" | "raw">(
    "breakdown"
  )
  const [showLegacy, setShowLegacy] = useState(() => {
    const active = status.strategies.find(
      (item) => item.name === status.active_strategy
    )
    // Тот же отказ от `overridden`: применение помечает пресет изменённым, и
    // блок «старые пресеты» переставал раскрываться ровно тогда, когда в нём
    // лежит применённая стратегия — то есть когда это и нужно.
    return Boolean(
      active?.builtin && parseNfqwsProfileMarker(active.content) === undefined
    )
  })
  // «Подробнее» на карточке профиля открывает разбор ниже по странице — и
  // должно туда доводить. Раньше кнопка только меняла выбранную стратегию:
  // на длинной странице разбор оставался за экраном, и нажатие выглядело
  // так, будто ничего не произошло. Счётчик, а не флаг: повторное нажатие
  // на ту же карточку тоже должно прокручивать.
  const detailsRef = useRef<HTMLDivElement>(null)
  const [detailsRequest, setDetailsRequest] = useState(0)
  useEffect(() => {
    if (detailsRequest === 0) return
    detailsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" })
  }, [detailsRequest])
  const openDetails = (name: string) => {
    setSelected(name)
    setEditorViewChoice("breakdown")
    setDetailsRequest((current) => current + 1)
  }
  const rawOnly = effectiveSelected.toLowerCase().endsWith(".list")
  const editorView = rawOnly ? "raw" : editorViewChoice
  const [creating, setCreating] = useState(false)
  const [deleting, setDeleting] = useState<string | null>(null)
  const [applying, setApplying] = useState<string | null>(null)
  const [snapshotting, setSnapshotting] = useState(false)
  const deletingIsOverride = Boolean(
    status.strategies.find((item) => item.name === deleting)?.overridden
  )
  // Пустой active_strategy означает, что nfqws2.conf не совпадает побайтово ни
  // с одной стратегией. Так бывает ровно в одном случае: конфигурацию правили
  // руками — на вкладке «Настройки» или по ssh. Раньше об этом сообщала плашка
  // над списком; со списком стратегий она пропала, и таблица показывала четыре
  // «не применена», ничего не объясняя.
  const customConfig = !status.active_strategy
  // Текущий nfqws2.conf держим под рукой, чтобы его можно было сохранить
  // стратегией до того, как «Применить» его перезапишет.
  const activeConfigQuery = useQuery({
    queryKey: [
      "nfqws",
      "file",
      "config",
      "nfqws2.conf",
      status.active_strategy,
    ],
    queryFn: () =>
      nfqwsAction<{ content: string }>({
        action: "read_file",
        category: "config",
        name: "nfqws2.conf",
      }),
  })
  const saveActiveAsStrategy = async (name: string) => {
    const activeContent = activeConfigQuery.data?.content
    if (activeContent === undefined) return
    try {
      await nfqwsAction({
        action: "save_strategy",
        name,
        content: activeContent,
      })
      toast.success(t("nfqws.saved"))
      refresh()
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      toast.error(message, { richColors: true })
    }
  }
  const contentOf = (name: string) =>
    draftContent[name] ??
    status.strategies.find((item) => item.name === name)?.content ??
    ""
  const showLiveRotatorState =
    effectiveSelected === status.active_strategy &&
    !Object.hasOwn(draftContent, effectiveSelected) &&
    activeConfigQuery.data?.content !== undefined
  const breakdownContent = showLiveRotatorState
    ? (activeConfigQuery.data?.content ?? content)
    : content
  const run = async (action: string, name: string) => {
    if (action === "apply_strategy") {
      const completed = await runOperation(
        t("nfqws.applyStrategy"),
        () =>
          nfqwsAction({
            action,
            name,
            content: contentOf(name),
          }),
        t("nfqws.strategyAppliedAndRestarted")
      )
      if (completed) {
        // nfqws2.conf теперь другой — снимок для «Сохранить текущую» должен
        // приехать заново, иначе кнопка сохранит то, что уже перезаписано.
        await queryClient.invalidateQueries({ queryKey: ["nfqws", "file"] })
        refresh()
      }
      return
    }
    try {
      await nfqwsAction<{ ok: boolean; output?: string }>({
        action,
        name,
        content: contentOf(name),
      })
      if (action === "save_strategy" || action === "delete_strategy") {
        setDraftContent((current) => {
          const next = { ...current }
          delete next[name]
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
  const names = [
    ...new Set([
      ...status.strategies.map((item) => item.name),
      ...Object.keys(draftContent),
    ]),
  ]

  const managedProfiles = status.strategies
    .flatMap((item) => {
      const hasChangedDraft =
        Object.hasOwn(draftContent, item.name) &&
        draftContent[item.name] !== item.content
      const tier = hasChangedDraft ? undefined : canonicalNfqwsProfileTier(item)
      return tier
        ? [
            {
              name: item.name,
              tier,
              content: item.content,
              active: item.name === status.active_strategy,
              modified: !nfqwsProfileMatchesPackage(item),
            },
          ]
        : []
    })
    .sort((left, right) => {
      const tierOrder =
        NFQWS_PROFILE_ORDER.indexOf(left.tier) -
        NFQWS_PROFILE_ORDER.indexOf(right.tier)
      return tierOrder || left.name.localeCompare(right.name)
    })
  const profileNames = new Set(managedProfiles.map((profile) => profile.name))
  const legacyNames = names.filter((name) => {
    const item = status.strategies.find((candidate) => candidate.name === name)
    const hasChangedDraft =
      item !== undefined &&
      Object.hasOwn(draftContent, name) &&
      draftContent[name] !== item.content
    // Ни `overridden`, ни `canonical` здесь не участвуют. Старый пресет —
    // это встроенная стратегия без маркера профиля, и он остаётся ею,
    // сколько бы раз его ни применяли и ни правили: происхождение
    // («Встроенная, изменена») видно в колонке строки, а место записи от
    // этого не меняется. Пока флаги участвовали, пресет уезжал из
    // сворачиваемого блока в «Свои и изменённые» — и владелец видел все
    // десять ver* развёрнутым списком, потому что `canonical` на роутере
    // ложный у каждой невзятой в работу встроенной стратегии.
    return Boolean(
      item?.builtin &&
      !hasChangedDraft &&
      parseNfqwsProfileMarker(item.content) === undefined
    )
  })
  const legacySet = new Set(legacyNames)
  const customNames = names.filter(
    (name) => !profileNames.has(name) && !legacySet.has(name)
  )
  const activeIsLegacy = legacySet.has(status.active_strategy)

  const legacyExpanded = activeIsLegacy || showLegacy
  const displayStrategyName = (name: string | null): string => {
    if (!name) return ""
    const item = status.strategies.find((candidate) => candidate.name === name)
    const key = item ? nfqwsBuiltinStrategyDisplayKey(item) : undefined
    return key ? t(`nfqws.strategyDisplayNames.${key}`) : name
  }

  const strategyRow = (name: string): ReactNode[] => {
    const item = status.strategies.find((candidate) => candidate.name === name)
    const isActive = name === status.active_strategy
    const isDraft = item === undefined
    const isEditing = name === effectiveSelected

    return [
      <button
        className={cn(
          "flex w-full min-w-0 cursor-pointer items-center gap-2 text-left font-mono",
          isEditing && "font-bold"
        )}
        key="name"
        onClick={() => setSelected(name)}
        type="button"
      >
        <span className="truncate">{displayStrategyName(name)}</span>
      </button>,
      <span className="text-xs text-muted-foreground" key="origin">
        {isDraft
          ? t("nfqws.strategyOrigin.draft")
          : item.builtin && item.overridden
            ? t("nfqws.strategyOrigin.overridden")
            : item.builtin
              ? t("nfqws.strategyOrigin.builtin")
              : t("nfqws.strategyOrigin.custom")}
      </span>,
      isActive ? (
        <KeeneticStatus key="state" tone="success">
          {t("nfqws.strategyState.active")}
        </KeeneticStatus>
      ) : (
        <span className="text-xs text-muted-foreground" key="state">
          {t("nfqws.strategyState.inactive")}
        </span>
      ),
      <span className="flex items-center justify-end gap-1" key="actions">
        <Button
          aria-label={t("nfqws.applyStrategy")}
          disabled={isDraft}
          onClick={() => {
            setSelected(name)
            setApplying(name)
          }}
          size="sm"
          title={
            isDraft
              ? t("nfqws.strategySaveBeforeApply")
              : t("nfqws.applyStrategy")
          }
          variant="outline"
        >
          <PlayIcon />
          {t("nfqws.applyStrategy")}
        </Button>
        <span className="keen-row-actions flex items-center gap-1">
          <Button
            aria-label={t("nfqws.editStrategy")}
            className="keen-row-action size-8 rounded-[4px]"
            onClick={() => setSelected(name)}
            size="icon"
            title={t("nfqws.editStrategy")}
            variant="outline"
          >
            <KeenPencilIcon className="size-4" />
          </Button>
          <Button
            aria-label={t("common.delete")}
            className="keen-row-action keen-row-action--danger size-8 rounded-[4px]"
            onClick={() => setDeleting(name)}
            size="icon"
            title={
              item?.builtin && item.overridden
                ? t("nfqws.restoreBuiltin")
                : t("common.delete")
            }
            variant="outline"
          >
            <KeenTrashIcon className="size-4" />
          </Button>
        </span>
      </span>,
    ]
  }
  const strategyColumnClassNames = [
    "w-full [&:where(td)]:max-w-0",
    "min-w-[10rem]",
    "min-w-[10rem]",
    undefined,
  ]
  const strategyHeaders = [
    t("nfqws.strategyHeaders.name"),
    t("nfqws.strategyHeaders.origin"),
    t("nfqws.strategyHeaders.state"),
    t("nfqws.strategyHeaders.actions"),
  ]

  return (
    <div className="space-y-3">
      <SectionHeading
        description={t("nfqws.strategiesDescription")}
        title={t("nfqws.strategiesTitle")}
      />
      <PageActionBar
        primary={
          <Button onClick={() => setCreating(true)}>
            <FilePlusIcon />
            {t("nfqws.addStrategy")}
          </Button>
        }
      >
        {/* Подпись длиннее половины экрана, а кнопки в панели действий на
            телефоне встают по две в ряд — текст вылезал за рамку. Этой отдаём
            строку целиком, как главному действию. */}
        <div className="col-span-2 *:w-full sm:col-auto sm:*:w-auto">
          <Button
            disabled={activeConfigQuery.data === undefined}
            onClick={() => setSnapshotting(true)}
            variant="outline"
          >
            <SaveIcon />
            {t("nfqws.snapshotActive")}
          </Button>
        </div>
      </PageActionBar>

      {/* Своя конфигурация — не ошибка, но и не то, что человек предполагает,
          глядя на четыре «не применена». Заодно это единственный случай, когда
          «Применить» уничтожает то, чего больше нигде нет. */}
      {customConfig ? (
        <Alert>
          <AlertTitle>{t("nfqws.customConfigTitle")}</AlertTitle>
          <AlertDescription>
            {t("nfqws.customConfigDescription")}
          </AlertDescription>
        </Alert>
      ) : null}

      {/* Three current profiles stay prominent. Custom, overridden and unknown
          entries remain in a full table; only untouched legacy built-ins may
          be collapsed. */}
      {names.length === 0 ? (
        <ListPlaceholder
          action={
            <Button onClick={() => setCreating(true)}>
              <FilePlusIcon />
              {t("nfqws.addStrategy")}
            </Button>
          }
          description={t("nfqws.strategiesEmpty")}
          title={t("nfqws.strategiesEmptyTitle")}
        />
      ) : (
        <div className="space-y-5">
          <NfqwsProfileCards
            onApply={(name) => {
              setSelected(name)
              setApplying(name)
            }}
            onOpen={openDetails}
            // Тот же диалог, что у карандаша в таблице: «Вернуть встроенную»
            // отбрасывает пользовательскую копию и возвращает файл поставки.
            onRestore={setDeleting}
            profiles={managedProfiles}
          />

          {customNames.length > 0 ? (
            <div className="space-y-2">
              <SectionHeading
                size="compact"
                title={t("nfqws.customStrategiesTitle")}
              />
              <DataTable
                columnClassNames={strategyColumnClassNames}
                headers={strategyHeaders}
                narrowColumns={[1, 2]}
                rows={customNames.map(strategyRow)}
              />
            </div>
          ) : null}

          {legacyNames.length > 0 ? (
            <div className="space-y-2">
              {!activeIsLegacy ? (
                <div className="flex justify-start">
                  <Button
                    onClick={() => setShowLegacy((current) => !current)}
                    size="sm"
                    variant="ghost"
                  >
                    {legacyExpanded ? (
                      <ChevronDownIcon />
                    ) : (
                      <ChevronRightIcon />
                    )}
                    {legacyExpanded
                      ? t("nfqws.legacyHide")
                      : t("nfqws.legacyShow", { count: legacyNames.length })}
                  </Button>
                </div>
              ) : null}
              {legacyExpanded ? (
                <div className="space-y-2">
                  <p className="text-xs text-muted-foreground">
                    {t("nfqws.legacyDescription")}
                  </p>
                  <DataTable
                    columnClassNames={strategyColumnClassNames}
                    headers={strategyHeaders}
                    narrowColumns={[1, 2]}
                    rows={legacyNames.map(strategyRow)}
                  />
                </div>
              ) : null}
            </div>
          ) : null}
        </div>
      )}

      {effectiveSelected ? (
        <div className="scroll-mt-4 space-y-3" ref={detailsRef}>
          <div className="flex flex-wrap items-start justify-between gap-3">
            <SectionHeading
              description={
                editorView === "breakdown"
                  ? t("nfqws.strategyBreakdownDescription")
                  : t("nfqws.strategyEditorDescription")
              }
              size="compact"
              title={
                editorView === "breakdown"
                  ? t("nfqws.strategyBreakdownTitle", {
                      name: displayStrategyName(effectiveSelected),
                    })
                  : t("nfqws.strategyEditorTitle", {
                      name: displayStrategyName(effectiveSelected),
                    })
              }
            />
            {!rawOnly ? (
              <SegmentedControl
                ariaLabel={t("nfqws.editorView.ariaLabel")}
                onChange={setEditorViewChoice}
                options={[
                  {
                    value: "breakdown",
                    label: t("nfqws.editorView.breakdown"),
                  },
                  { value: "raw", label: t("nfqws.editorView.raw") },
                ]}
                value={editorView}
              />
            ) : null}
          </div>
          {editorView === "breakdown" ? (
            <StrategyBreakdown
              content={breakdownContent}
              rotatorState={
                showLiveRotatorState ? status.rotator_state : undefined
              }
            />
          ) : (
            <CodeEditor
              className="h-[50vh] max-h-[40rem] min-h-[18rem]"
              onChange={(next) =>
                setDraftContent((current) => ({
                  ...current,
                  [effectiveSelected]: next,
                }))
              }
              syntax={rawOnly ? "list" : "nfqws"}
              value={content}
            />
          )}
          <div className="flex flex-wrap justify-end gap-2">
            <Button
              onClick={() => void run("save_strategy", effectiveSelected)}
              variant="outline"
            >
              <SaveIcon />
              {t("nfqws.saveStrategy")}
            </Button>
            <Button
              disabled={selectedIsApplied}
              onClick={() => setApplying(effectiveSelected)}
              title={
                selectedIsApplied
                  ? t("nfqws.strategyAlreadyApplied")
                  : t("nfqws.applyStrategy")
              }
            >
              <PlayIcon />
              {selectedIsApplied
                ? t("nfqws.profiles.applied")
                : t("nfqws.applyStrategy")}
            </Button>
          </div>
        </div>
      ) : null}

      <NfqwsNameDialog
        confirmLabel={t("nfqws.addStrategy")}
        description={t("nfqws.strategyNameDescription")}
        label={t("nfqws.strategyName")}
        onOpenChange={setCreating}
        onSubmit={(name) => {
          setSelected(name)
          setDraftContent((current) => ({ ...current, [name]: "" }))
        }}
        open={creating}
        placeholder="my-strategy"
        title={t("nfqws.addStrategy")}
      />
      <NfqwsNameDialog
        confirmLabel={t("nfqws.snapshotActive")}
        description={t("nfqws.snapshotActiveDescription")}
        label={t("nfqws.strategyName")}
        onOpenChange={setSnapshotting}
        onSubmit={(name) => void saveActiveAsStrategy(name)}
        open={snapshotting}
        placeholder="my-current-config"
        title={t("nfqws.snapshotActive")}
      />
      <NfqwsConfirmDialog
        confirmLabel={t("nfqws.applyStrategy")}
        description={
          customConfig
            ? t("nfqws.applyOverCustomDescription", {
                name: displayStrategyName(applying),
              })
            : t("nfqws.applyDescription", {
                name: displayStrategyName(applying),
              })
        }
        destructive={customConfig}
        onConfirm={() => {
          if (applying) void run("apply_strategy", applying)
          setApplying(null)
        }}
        onOpenChange={(open) => !open && setApplying(null)}
        open={applying !== null}
        title={t("nfqws.applyConfirmTitle")}
      />
      <NfqwsConfirmDialog
        confirmLabel={t("common.delete")}
        description={
          deletingIsOverride
            ? t("nfqws.restoreBuiltinDescription", {
                name: displayStrategyName(deleting),
              })
            : t("nfqws.deleteStrategyDescription", {
                name: displayStrategyName(deleting),
              })
        }
        onConfirm={() => {
          if (deleting) void run("delete_strategy", deleting)
          setDeleting(null)
        }}
        onOpenChange={(open) => !open && setDeleting(null)}
        open={deleting !== null}
        title={
          deletingIsOverride
            ? t("nfqws.restoreBuiltin")
            : t("nfqws.deleteStrategyTitle")
        }
      />
    </div>
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
  const [creating, setCreating] = useState(false)
  const [deleting, setDeleting] = useState<NfqwsFile | null>(null)
  const [clearing, setClearing] = useState<NfqwsFile | null>(null)
  const create = async (stem: string) => {
    const extension = category === "lua" ? ".lua" : ".list"
    const name = stem.endsWith(extension) ? stem : stem + extension
    await nfqwsAction({ action: "create_file", category, name, content: "" })
    setSelected(name)
    refresh()
  }
  const remove = async (file: NfqwsFile) => {
    await nfqwsAction({ action: "delete_file", category, name: file.name })
    if (editableCategory) onDraftRemove(category, file.name)
    setSelected("")
    refresh()
  }
  const clearLog = async (file: NfqwsFile) => {
    await nfqwsAction({ action: "clear_log", name: file.name })
    await queryClient.invalidateQueries({ queryKey: ["nfqws", "file"] })
    toast.success(t("nfqws.logCleared"))
    refresh()
  }
  const tabKey =
    category === "list" ? "lists" : category === "lua" ? "lua" : "logs"

  return (
    <div className="space-y-3">
      <SectionHeading
        description={t(`nfqws.fileSections.${tabKey}`)}
        title={t(`nfqws.tabs.${tabKey}`)}
      />
      {!readonly ? (
        <PageActionBar
          primary={
            <Button onClick={() => setCreating(true)}>
              <FilePlusIcon />
              {t("nfqws.newFile")}
            </Button>
          }
        />
      ) : null}

      {/* Файлы списком, а не выпадающим меню: имя файла ничего не говорит о
          том, что внутри и когда его правили в последний раз, а из свёрнутого
          меню не видно даже сколько их. */}
      {available.length === 0 ? (
        <ListPlaceholder
          action={
            readonly ? undefined : (
              <Button onClick={() => setCreating(true)}>
                <FilePlusIcon />
                {t("nfqws.newFile")}
              </Button>
            )
          }
          description={t(`nfqws.fileEmpty.${tabKey}`)}
          title={t("nfqws.fileEmptyTitle")}
        />
      ) : (
        <DataTable
          columnClassNames={[
            "w-full [&:where(td)]:max-w-0",
            "min-w-[8rem]",
            undefined,
          ]}
          headers={[
            t("nfqws.fileHeaders.name"),
            t("nfqws.fileHeaders.size"),
            t("nfqws.fileHeaders.actions"),
          ]}
          narrowColumns={[1]}
          rows={available.map((file) => {
            const isEditing = file.name === current?.name
            const hasDraft = Object.hasOwn(
              drafts,
              `${file.category}/${file.name}`
            )

            return [
              <button
                className={cn(
                  "flex w-full min-w-0 cursor-pointer items-center gap-2 text-left font-mono",
                  isEditing && "font-bold"
                )}
                key="name"
                onClick={() => setSelected(file.name)}
                type="button"
              >
                <span className="truncate">{file.name}</span>
                {hasDraft ? (
                  <Badge size="xs" variant="warning">
                    {t("nfqws.fileDraftBadge")}
                  </Badge>
                ) : null}
              </button>,
              <span
                className="text-xs text-muted-foreground tabular-nums"
                key="size"
              >
                {formatFileSize(file.size)}
              </span>,
              <span
                className="keen-row-actions flex items-center justify-end gap-1"
                key="acts"
              >
                <Button
                  aria-label={t("nfqws.openFile")}
                  className="keen-row-action size-8 rounded-[4px]"
                  onClick={() => setSelected(file.name)}
                  size="icon"
                  title={t("nfqws.openFile")}
                  variant="outline"
                >
                  <KeenPencilIcon className="size-4" />
                </Button>
                {category === "log" ? (
                  <Button
                    aria-label={t("nfqws.clearLog")}
                    className="keen-row-action size-8 rounded-[4px]"
                    onClick={() => setClearing(file)}
                    size="icon"
                    title={t("nfqws.clearLog")}
                    variant="outline"
                  >
                    <EraserIcon className="size-4" />
                  </Button>
                ) : null}
                <Button
                  aria-label={t("common.delete")}
                  className={cn(
                    "keen-row-action size-8 rounded-[4px]",
                    file.removable && "keen-row-action--danger"
                  )}
                  disabled={!file.removable}
                  onClick={() => setDeleting(file)}
                  size="icon"
                  title={
                    file.removable
                      ? t("common.delete")
                      : t("nfqws.fileNotRemovable")
                  }
                  variant="outline"
                >
                  <KeenTrashIcon className="size-4" />
                </Button>
              </span>,
            ]
          })}
        />
      )}

      {current ? (
        <div className="space-y-3">
          <SectionHeading
            size="compact"
            title={t("nfqws.fileEditorTitle", { name: current.name })}
          />
          {fileQuery.isLoading ? (
            <Skeleton className="h-[40vh] max-h-[36rem] min-h-[16rem] w-full" />
          ) : (
            <CodeEditor
              className="h-[50vh] max-h-[40rem] min-h-[18rem]"
              onChange={(next) => {
                if (category === "list" || category === "lua")
                  onDraftChange({ category, name: current.name, content: next })
              }}
              readOnly={readonly}
              syntax={readonly ? "log" : "nfqws"}
              value={content}
            />
          )}
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
      ) : null}

      <NfqwsNameDialog
        confirmLabel={t("nfqws.newFile")}
        description={t(`nfqws.fileNameDescription.${tabKey}`)}
        label={t("nfqws.fileName")}
        onOpenChange={setCreating}
        onSubmit={(name) => void create(name)}
        open={creating}
        placeholder={category === "lua" ? "my-script.lua" : "my-list.list"}
        title={t("nfqws.newFile")}
      />
      <NfqwsConfirmDialog
        confirmLabel={t("common.delete")}
        description={t("nfqws.deleteFileDescription", {
          name: deleting?.name ?? "",
        })}
        onConfirm={() => {
          if (deleting) void remove(deleting)
          setDeleting(null)
        }}
        onOpenChange={(open) => !open && setDeleting(null)}
        open={deleting !== null}
        title={t("nfqws.deleteFileTitle")}
      />
      <NfqwsConfirmDialog
        confirmLabel={t("nfqws.clearLog")}
        description={t("nfqws.clearLogDescription", {
          name: clearing?.name ?? "",
        })}
        onConfirm={() => {
          if (clearing) void clearLog(clearing)
          setClearing(null)
        }}
        onOpenChange={(open) => !open && setClearing(null)}
        open={clearing !== null}
        title={t("nfqws.clearLog")}
      />
    </div>
  )
}

function formatFileSize(bytes: number) {
  if (!Number.isFinite(bytes) || bytes < 0) return "—"
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

/** Имя новой стратегии или файла — вместо window.prompt, который выглядит как
 *  системное окно браузера и не умеет ни подсказки, ни примера. */
function NfqwsNameDialog({
  confirmLabel,
  description,
  label,
  onOpenChange,
  onSubmit,
  open,
  placeholder,
  title,
}: {
  confirmLabel: string
  description?: string
  label: string
  onOpenChange: (open: boolean) => void
  onSubmit: (name: string) => void
  open: boolean
  placeholder?: string
  title: string
}) {
  const { t } = useTranslation()
  const [name, setName] = useState("")
  // Чистим поле при закрытии, а не при открытии: через onOpenChange проходят и
  // Esc, и клик мимо окна, и «Отмена», так что в следующий раз окно открывается
  // пустым без эффекта, гоняющего лишний рендер.
  const changeOpen = (next: boolean) => {
    if (!next) setName("")
    onOpenChange(next)
  }

  const submit = () => {
    const trimmed = name.trim()
    if (!trimmed) return
    onSubmit(trimmed)
    changeOpen(false)
  }

  return (
    <Dialog onOpenChange={changeOpen} open={open}>
      <DialogContent showCloseButton={false}>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          {description ? (
            <DialogDescription>{description}</DialogDescription>
          ) : null}
        </DialogHeader>
        <div className="grid gap-1.5">
          <Label htmlFor="nfqws-name-dialog">{label}</Label>
          <Input
            autoFocus
            id="nfqws-name-dialog"
            onChange={(event) => setName(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter") {
                event.preventDefault()
                submit()
              }
            }}
            placeholder={placeholder}
            value={name}
          />
        </div>
        <DialogFooter>
          <Button onClick={() => changeOpen(false)} variant="outline">
            {t("common.cancel")}
          </Button>
          <Button disabled={!name.trim()} onClick={submit}>
            {confirmLabel}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** Подтверждение удаления — вместо window.confirm: тот показывает адрес
 *  роутера вместо названия панели и не говорит, что именно будет удалено. */
function NfqwsConfirmDialog({
  confirmLabel,
  description,
  destructive = true,
  onConfirm,
  onOpenChange,
  open,
  title,
}: {
  confirmLabel: string
  description: string
  /** Красная кнопка — только там, где действие правда необратимо. */
  destructive?: boolean
  onConfirm: () => void
  onOpenChange: (open: boolean) => void
  open: boolean
  title: string
}) {
  const { t } = useTranslation()

  return (
    <Dialog onOpenChange={onOpenChange} open={open}>
      <DialogContent showCloseButton={false}>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button onClick={() => onOpenChange(false)} variant="outline">
            {t("common.cancel")}
          </Button>
          <Button
            onClick={onConfirm}
            variant={destructive ? "destructive" : "default"}
          >
            {confirmLabel}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
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
      {/* На телефоне заголовок и плашки состояния идут друг под другом. Пока
          они стояли в один ряд, плашки были `shrink-0` и забирали почти всю
          ширину — заголовку оставалось столько, что «Служба nfqws2» и
          «Установленная версия: 1.2.4» ломались посреди слова. */}
      <div className="flex min-w-0 flex-col gap-2 sm:flex-row sm:items-start sm:justify-between sm:gap-3">
        <SectionHeading description={description} title={title} />
        {action ? <div className="sm:shrink-0">{action}</div> : null}
      </div>
      {children}
    </section>
  )
}

/**
 * Редкие действия под одной кнопкой: обновление пакета, точки возврата,
 * резервные копии, перечитывание конфигурации.
 *
 * Пояснение стоит у самого пункта, а не только под знаком вопроса у
 * заголовка: решение принимается здесь, и разница между «Сохранить точку
 * возврата» и «Резервные копии» должна читаться в момент выбора. Недоступный
 * пункт говорит причину вместо объяснения, зачем он нужен, — иначе человек
 * читает, что кнопка делает, и не понимает, почему она не нажимается.
 */
function NfqwsMaintenanceMenu({
  items,
}: {
  items: readonly {
    key: string
    icon: typeof ArchiveIcon
    label: string
    hint: string
    disabled?: boolean
    disabledReason?: string
    onSelect: () => void
  }[]
}) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)

  return (
    <Popover onOpenChange={setOpen} open={open}>
      <PopoverTrigger
        render={
          <Button
            aria-label={t("nfqws.maintenance")}
            title={t("nfqws.maintenanceHint")}
            variant="outline"
          />
        }
      >
        <WrenchIcon />
        {t("nfqws.maintenance")}
        <ChevronDownIcon className="size-3.5 opacity-60" />
      </PopoverTrigger>
      <PopoverContent align="start" className="w-80 p-0 py-1">
        <div className="flex flex-col">
          {items.map((item) => {
            const Icon = item.icon
            const reason = item.disabled ? item.disabledReason : undefined
            return (
              <button
                className="flex w-full items-start gap-2.5 px-3 py-2 text-left outline-none hover:bg-accent focus-visible:bg-accent disabled:pointer-events-none disabled:opacity-50"
                disabled={item.disabled}
                key={item.key}
                onClick={() => {
                  setOpen(false)
                  item.onSelect()
                }}
                type="button"
              >
                <Icon className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
                <span className="min-w-0">
                  <span className="block text-sm font-medium">
                    {item.label}
                  </span>
                  <span className="block text-xs text-muted-foreground">
                    {reason ?? item.hint}
                  </span>
                </span>
              </button>
            )
          })}
        </div>
      </PopoverContent>
    </Popover>
  )
}

/**
 * Что делает каждая кнопка службы — списком «подпись → объяснение».
 *
 * Развёрнуто, потому что разница между «Перезапустить службу» и «Перечитать
 * конфигурацию» — это разница между «соединения оборвутся» и «не оборвутся»,
 * и по одним подписям её не восстановить. Тот же текст висит в `title` на
 * каждой кнопке — для мыши.
 */
function ServiceActionsHelp() {
  const { t } = useTranslation()

  return (
    <dl className="grid gap-2.5">
      <div>
        <dt className="font-medium">{t("nfqws.stop")}</dt>
        <dd className="text-muted-foreground">
          {t("nfqws.serviceHelp.toggle")}
        </dd>
      </div>
      <div>
        <dt className="font-medium">{t("nfqws.restart")}</dt>
        <dd className="text-muted-foreground">
          {t("nfqws.serviceHelp.restart")}
        </dd>
      </div>
      <div>
        <dt className="font-medium">{t("nfqws.refresh")}</dt>
        <dd className="text-muted-foreground">
          {t("nfqws.serviceHelp.refresh")}
        </dd>
      </div>
      <div>
        <dt className="font-medium">{t("nfqws.upgrade")}</dt>
        <dd className="text-muted-foreground">
          {t("nfqws.serviceHelp.upgrade")}
        </dd>
      </div>
      <div>
        <dt className="font-medium">{t("nfqws.maintenance")}</dt>
        <dd className="text-muted-foreground">
          {t("nfqws.serviceHelp.maintenance")}
        </dd>
      </div>
    </dl>
  )
}

const ARGS_COLLAPSE_THRESHOLD = 240

function ArgsField({
  help,
  hint,
  label,
  value,
  variable,
  onChange,
}: {
  /** Что это за аргументы вообще — под знаком вопроса, а не строкой под полем. */
  help?: string
  hint?: string
  label: string
  value: string
  variable?: string
  onChange: (next: string) => void
}) {
  const { t } = useTranslation()
  const [expanded, setExpanded] = useState(false)
  const [copied, setCopied] = useState(false)
  const collapsible = value.length > ARGS_COLLAPSE_THRESHOLD
  const open = expanded || !collapsible
  const argumentCount = value
    .split(/\s+/)
    .filter((token) => token.startsWith("--")).length

  return (
    // Компактная ширина, как у всех полей настроек (решение владельца):
    // пусть страница длиннее, но в едином стиле.
    <div className="grid max-w-[480px] gap-1.5">
      <div className="flex flex-wrap items-center gap-2">
        <Label className="flex flex-wrap items-center gap-2">
          {label}
          {variable ? (
            <span className="font-mono text-[11px] font-normal text-muted-foreground">
              {variable}
            </span>
          ) : null}
          {help ? <HelpHint text={help} /> : null}
        </Label>
        {collapsible ? (
          <>
            {/* Кнопки в размер остальных кнопок панели: здесь стояли 28px —
                единственные во всём интерфейсе. */}
            <Button
              onClick={() => setExpanded((current) => !current)}
              size="sm"
              type="button"
              variant="ghost"
            >
              {expanded ? t("nfqws.hideArgs") : t("nfqws.showArgs")}
              <ChevronDownIcon
                className={cn(
                  "size-3.5 transition-transform",
                  expanded && "rotate-180"
                )}
              />
            </Button>
            <Button
              onClick={() => {
                void copyText(value).then((ok) => {
                  setCopied(ok)
                  window.setTimeout(() => setCopied(false), 1500)
                })
              }}
              size="sm"
              type="button"
              variant="ghost"
            >
              {copied ? t("common.copied") : t("common.copy")}
            </Button>
          </>
        ) : null}
      </div>
      {open ? (
        <CodeEditor
          className="min-h-24"
          onChange={onChange}
          syntax="nfqws"
          value={value}
        />
      ) : (
        <Button
          className="h-auto w-full justify-start px-3 py-2 text-left text-xs font-normal whitespace-normal text-muted-foreground"
          onClick={() => setExpanded(true)}
          type="button"
          variant="outline"
        >
          {t("nfqws.argsSummary", {
            count: argumentCount,
            chars: value.length,
          })}
        </Button>
      )}
      {hint ? <p className="text-xs text-muted-foreground">{hint}</p> : null}
    </div>
  )
}

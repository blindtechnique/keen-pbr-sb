import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import {
  DownloadIcon,
  FilePlusIcon,
  PlayIcon,
  RefreshCwIcon,
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
  formatNfqwsConfig,
  parseNfqwsConfig,
  type NfqwsConfigForm,
} from "@/lib/nfqws-config"

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

async function nfqwsAction<T = { ok: boolean; output?: string }>(
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
  const [tab, setTab] = useState<Tab>("settings")
  const [operationResult, setOperationResult] = useState("")
  const mutation = useMutation({
    mutationFn: (payload: Record<string, unknown>) => nfqwsAction(payload),
    onSuccess: async (result) => {
      await queryClient.invalidateQueries({ queryKey: ["nfqws"] })
      setOperationResult(result.output?.trim() || t("nfqws.operationCompleted"))
    },
    onError: (error) => {
      setOperationResult(error.message)
      toast.error(error.message, { richColors: true })
    },
  })

  return (
    <div className="space-y-3">
      <PageHeader
        actions={
          <Button
            disabled={query.isFetching}
            onClick={() => void query.refetch()}
            variant="outline"
          >
            <RefreshCwIcon className={query.isFetching ? "animate-spin" : ""} />
            {t("nfqws.refresh")}
          </Button>
        }
        description={t("nfqws.description")}
        title="nfqws2"
      />

      {!status?.installed && !query.isLoading ? <NotInstalled /> : null}

      {status?.installed ? (
        <>
          <Card>
            <CardHeader>
              <CardTitle>{t("nfqws.service")}</CardTitle>
              <CardDescription>
                {t("nfqws.version", { version: status.version || "—" })}
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
                  aria-label={status.running ? t("nfqws.stop") : t("nfqws.start")}
                  checked={status.running}
                  disabled={mutation.isPending}
                  onCheckedChange={(checked) =>
                    mutation.mutate({
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
                disabled={mutation.isPending}
                onClick={() =>
                  mutation.mutate({ action: "service", command: "restart" })
                }
                variant="outline"
              >
                <RefreshCwIcon />
                {t("nfqws.restart")}
              </Button>
              <Button
                disabled={mutation.isPending}
                onClick={() =>
                  mutation.mutate({ action: "service", command: "reload" })
                }
                variant="outline"
              >
                {t("nfqws.reload")}
              </Button>
              <Button
                disabled={mutation.isPending}
                onClick={() => mutation.mutate({ action: "upgrade" })}
                variant="outline"
              >
                <DownloadIcon />
                {t("nfqws.upgrade")}
              </Button>
              </div>
            </CardContent>
          </Card>

          {operationResult ? (
            <Alert>
              <AlertTitle>{t("nfqws.operationResult")}</AlertTitle>
              <AlertDescription className="space-y-3">
                <pre className="max-h-72 overflow-auto whitespace-pre-wrap rounded-md bg-muted p-3 text-xs text-foreground">
                  {operationResult}
                </pre>
                <Button
                  onClick={() => setOperationResult("")}
                  size="sm"
                  variant="outline"
                >
                  {t("nfqws.closeResult")}
                </Button>
              </AlertDescription>
            </Alert>
          ) : null}

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
              onOperationResult={setOperationResult}
              status={status}
              refresh={() => void query.refetch()}
            />
          ) : null}
          {tab === "lists" ? (
            <FilesEditor
              category="list"
              files={status.files}
              refresh={() => void query.refetch()}
            />
          ) : null}
          {tab === "lua" ? (
            <FilesEditor
              category="lua"
              files={status.files}
              refresh={() => void query.refetch()}
            />
          ) : null}
          {tab === "logs" ? (
            <FilesEditor
              category="log"
              files={status.files}
              refresh={() => void query.refetch()}
              readonly
            />
          ) : null}
          {tab === "check" ? <UrlCheck /> : null}
        </>
      ) : null}
    </div>
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
  const [source, setSource] = useState("")
  const [form, setForm] = useState<NfqwsConfigForm | null>(null)
  useEffect(() => {
    if (file)
      void readFile(file).then(({ content }) => {
        setSource(content)
        setForm(parseNfqwsConfig(content))
      })
  }, [file?.name])
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
  onOperationResult,
  status,
  refresh,
}: {
  onOperationResult: (output: string) => void
  status: Status
  refresh: () => void
}) {
  const { t } = useTranslation()
  const preferredStrategy =
    status.active_strategy || status.strategies[0]?.name || ""
  const [selected, setSelected] = useState(preferredStrategy)
  const strategy = status.strategies.find((item) => item.name === selected)
  const [content, setContent] = useState(strategy?.content ?? "")
  useEffect(() => {
    if (!status.strategies.some((item) => item.name === selected))
      setSelected(preferredStrategy)
  }, [preferredStrategy, selected, status.strategies])
  useEffect(
    () => setContent(strategy?.content ?? ""),
    [strategy?.name, strategy?.content]
  )
  const add = () => {
    const name = window.prompt(t("nfqws.strategyName"))
    if (name) {
      setSelected(name)
      setContent("")
    }
  }
  const run = async (action: string) => {
    try {
      const result = await nfqwsAction<{ ok: boolean; output?: string }>({
        action,
        name: selected,
        content,
      })
      if (action === "apply_strategy")
        onOperationResult(
          result.output?.trim() || t("nfqws.strategyAppliedAndRestarted")
        )
      else toast.success(t("nfqws.saved"))
      refresh()
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      onOperationResult(message)
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
            value={selected}
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
          {selected && selected !== status.active_strategy ? (
            <span className="text-muted-foreground">
              {t("nfqws.selectedForEditing", { name: selected })}
            </span>
          ) : null}
        </div>
        <CodeEditor
          className="min-h-[30rem]"
          onChange={setContent}
          syntax={selected.endsWith(".list") ? "list" : "nfqws"}
          value={content}
        />
        <div className="flex flex-wrap justify-end gap-2">
          <Button
            disabled={!selected}
            onClick={() => void run("apply_strategy")}
          >
            <PlayIcon />
            {t("nfqws.applyStrategy")}
          </Button>
          <Button
            disabled={!selected}
            onClick={() => void run("save_strategy")}
            variant="outline"
          >
            <SaveIcon />
            {t("nfqws.saveStrategy")}
          </Button>
          <Button
            disabled={!selected}
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
  files,
  refresh,
  readonly = false,
}: {
  category: NfqwsFile["category"]
  files: NfqwsFile[]
  refresh: () => void
  readonly?: boolean
}) {
  const { t } = useTranslation()
  const available = useMemo(
    () => files.filter((item) => item.category === category),
    [files, category]
  )
  const [selected, setSelected] = useState(available[0]?.name ?? "")
  const [content, setContent] = useState("")
  const importRef = useRef<HTMLInputElement>(null)
  const current = available.find((item) => item.name === selected)
  useEffect(() => {
    const file =
      available.find((item) => item.name === selected) ?? available[0]
    if (file) {
      setSelected(file.name)
      void readFile(file).then((value) => setContent(value.content))
    }
  }, [selected, available.map((item) => item.name).join("|")])
  const save = async () => {
    if (!current) return
    await nfqwsAction({
      action: "save_file",
      category,
      name: current.name,
      content,
    })
    toast.success(t("nfqws.saved"))
    refresh()
  }
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
    setSelected("")
    refresh()
  }
  const clearLog = async () => {
    if (!current || !window.confirm(t("nfqws.confirmClearLog"))) return
    await nfqwsAction({ action: "clear_log", name: current.name })
    setContent("")
    toast.success(t("nfqws.logCleared"))
    refresh()
  }
  const exportAll = async () => {
    const bundle: Record<string, string> = {}
    for (const file of available)
      bundle[file.name] = (await readFile(file)).content
    const blob = new Blob(
      [
        JSON.stringify(
          { format: "keen-pbr-sb-nfqws-lists", version: 1, files: bundle },
          null,
          2
        ),
      ],
      { type: "application/json" }
    )
    const url = URL.createObjectURL(blob)
    const link = document.createElement("a")
    link.href = url
    link.download = "nfqws2-lists.json"
    link.click()
    URL.revokeObjectURL(url)
  }
  const importAll = async (file?: File) => {
    if (!file) return
    try {
      const parsed = JSON.parse(await file.text())
      if (parsed.format !== "keen-pbr-sb-nfqws-lists" || !parsed.files)
        throw new Error(t("configTransfer.invalidFormat"))
      await nfqwsAction({ action: "import_lists", files: parsed.files })
      toast.success(t("nfqws.saved"))
      refresh()
    } catch (error) {
      toast.error(
        error instanceof Error
          ? error.message
          : t("configTransfer.invalidFormat")
      )
    }
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
            value={selected}
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
          {category === "list" ? (
            <>
              <Button onClick={() => void exportAll()} variant="outline">
                <DownloadIcon />
                {t("configTransfer.export")}
              </Button>
              <Button
                onClick={() => importRef.current?.click()}
                variant="outline"
              >
                <UploadIcon />
                {t("configTransfer.import")}
              </Button>
              <input
                accept=".json,application/json"
                className="hidden"
                onChange={(event) => void importAll(event.target.files?.[0])}
                ref={importRef}
                type="file"
              />
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
          className="min-h-[30rem]"
          onChange={setContent}
          readOnly={readonly}
          syntax={readonly ? "log" : "nfqws"}
          value={content}
        />
        {!readonly ? (
          <div className="flex justify-end">
            <Button disabled={!current} onClick={() => void save()}>
              <SaveIcon />
              {t("nfqws.save")}
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
              result ? "border-success/40 bg-success/10 text-success" : undefined
            }
            variant={result ? "default" : "destructive"}
          >
            <AlertDescription
              className={result ? "text-success" : undefined}
            >
              {result ? t("nfqws.reachable") : t("nfqws.unreachable")}
            </AlertDescription>
          </Alert>
        ) : null}
      </CardContent>
    </Card>
  )
}

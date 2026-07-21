import { useCallback, useEffect, useRef, useState } from "react"
import { DownloadIcon, RotateCcwIcon, UploadIcon } from "lucide-react"
import { toast } from "sonner"

import { PageHeader } from "@/components/shared/page-header"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"

type BackupGroup =
  | "general"
  | "transports"
  | "outbounds"
  | "dns"
  | "routing"
  | "nfqws"

type BackupBundle = {
  format: "keen-pbr-sb-backup"
  schema: 1
  created_at: number
  groups: Record<BackupGroup, boolean>
  data: Record<string, unknown>
}

const GROUPS: ReadonlyArray<{ key: BackupGroup; label: string }> = [
  { key: "general", label: "Конфигурация общих настроек" },
  { key: "transports", label: "Транспорты" },
  { key: "outbounds", label: "Исходящие соединения" },
  { key: "dns", label: "Настройки DNS" },
  { key: "routing", label: "Списки и правила маршрутизации" },
  { key: "nfqws", label: "Конфигурация и списки nfqws2" },
]

async function apiJson<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, init)
  const body = (await response.json().catch(() => ({}))) as T & { error?: string }
  if (!response.ok) throw new Error(body.error ?? `HTTP ${response.status}`)
  return body
}

function downloadBundle(bundle: BackupBundle) {
  const blob = new Blob([JSON.stringify(bundle, null, 2) + "\n"], {
    type: "application/json",
  })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement("a")
  anchor.href = url
  anchor.download = `keen-pbr-sb-backup-${new Date().toISOString().slice(0, 10)}.json`
  anchor.click()
  URL.revokeObjectURL(url)
}

export function BackupPage() {
  const [groups, setGroups] = useState<Record<BackupGroup, boolean>>(
    Object.fromEntries(GROUPS.map(({ key }) => [key, true])) as Record<BackupGroup, boolean>
  )
  const [pending, setPending] = useState(false)

  const create = async () => {
    setPending(true)
    try {
      const bundle = await apiJson<BackupBundle>("/api/backup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ groups }),
      })
      downloadBundle(bundle)
      toast.success("Резервная копия создана")
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Не удалось создать копию")
    } finally {
      setPending(false)
    }
  }

  return (
    <>
      <PageHeader title="Резервная копия" description="Выберите данные и скачайте единый файл конфигурации keen-pbr-sb." />
      <Card className="max-w-3xl">
        <CardHeader>
          <CardTitle>Состав копии</CardTitle>
          <CardDescription>Файл может содержать секреты транспортов. Храните его в безопасном месте.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          <div className="grid gap-3 sm:grid-cols-2">
            {GROUPS.map(({ key, label }) => (
              <label className="flex cursor-pointer items-center gap-3 rounded-md border p-3" key={key}>
                <Checkbox checked={groups[key]} onCheckedChange={(checked) => setGroups((value) => ({ ...value, [key]: checked === true }))} />
                <span className="text-sm font-medium">{label}</span>
              </label>
            ))}
          </div>
          <Button disabled={pending || !Object.values(groups).some(Boolean)} onClick={() => void create()}>
            <DownloadIcon />{pending ? "Создание…" : "Создать и скачать"}
          </Button>
        </CardContent>
      </Card>
    </>
  )
}

export function RestorePage() {
  const inputRef = useRef<HTMLInputElement>(null)
  const [pending, setPending] = useState(false)
  const [rollbackAvailable, setRollbackAvailable] = useState(false)

  const refreshRollback = useCallback(async () => {
    const result = await apiJson<{ available: boolean }>("/api/backup/rollback")
    setRollbackAvailable(result.available)
  }, [])

  useEffect(() => { void refreshRollback() }, [refreshRollback])

  const restore = async (file?: File) => {
    if (!file) return
    setPending(true)
    try {
      const bundle = JSON.parse(await file.text()) as BackupBundle
      if (bundle.format !== "keen-pbr-sb-backup" || bundle.schema !== 1) throw new Error("Это не резервная копия keen-pbr-sb")
      if (!window.confirm("Восстановить выбранные разделы? Перед изменением будет автоматически создана rollback-копия.")) return
      await apiJson("/api/backup/restore", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(bundle) })
      toast.success("Конфигурация восстановлена")
      await refreshRollback()
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Восстановление не удалось")
    } finally {
      setPending(false)
      if (inputRef.current) inputRef.current.value = ""
    }
  }

  const rollback = async () => {
    if (!window.confirm("Откатить конфигурацию к состоянию перед последним обновлением или восстановлением?")) return
    setPending(true)
    try {
      await apiJson("/api/backup/rollback", { method: "POST" })
      toast.success("Откат выполнен")
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Откат не удался")
    } finally { setPending(false) }
  }

  return (
    <>
      <PageHeader title="Восстановление" description="Восстановите выбранные группы из файла или откатите последнее изменение." />
      <Card className="max-w-3xl">
        <CardHeader><CardTitle>Источник восстановления</CardTitle><CardDescription>Конфигурация проверяется до записи и применяется только после успешной валидации.</CardDescription></CardHeader>
        <CardContent className="flex flex-wrap gap-3">
          <Button disabled={pending} onClick={() => inputRef.current?.click()}><UploadIcon />Выбрать файл копии</Button>
          <Button disabled={pending || !rollbackAvailable} onClick={() => void rollback()} size="lg" variant="destructive"><RotateCcwIcon />Откат в один клик</Button>
          <input ref={inputRef} type="file" accept="application/json,.json" className="hidden" onChange={(event) => void restore(event.target.files?.[0])} />
        </CardContent>
      </Card>
    </>
  )
}

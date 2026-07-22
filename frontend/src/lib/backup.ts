import { downloadJson, formatDownloadTimestamp } from "@/lib/download"

export const BACKUP_GROUPS = [
  "general",
  "transports",
  "outbounds",
  "dns",
  "routing",
  "nfqws",
] as const

export type BackupGroup = (typeof BACKUP_GROUPS)[number]

export type BackupSelection = Record<BackupGroup, boolean>

export type BackupBundle = {
  format: "keen-pbr-sb-backup"
  schema: 1
  created_at: number
  groups: BackupSelection
  data: Record<string, unknown>
}

type ApiErrorBody = { error?: string }

export function createDefaultBackupSelection(): BackupSelection {
  return Object.fromEntries(
    BACKUP_GROUPS.map((group) => [group, true])
  ) as BackupSelection
}

export async function createBackup(
  groups: BackupSelection
): Promise<BackupBundle> {
  return apiJson<BackupBundle>("/api/backup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ groups }),
  })
}

export async function restoreBackup(bundle: BackupBundle): Promise<void> {
  await apiJson("/api/backup/restore", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(bundle),
  })
}

export async function getRollbackAvailability(): Promise<boolean> {
  const result = await apiJson<{ available: boolean }>("/api/backup/rollback")
  return result.available
}

export async function rollbackBackup(): Promise<void> {
  await apiJson("/api/backup/rollback", { method: "POST" })
}

export async function readBackupFile(file: File): Promise<BackupBundle> {
  const parsed: unknown = JSON.parse(await file.text())
  if (!isBackupBundle(parsed)) {
    throw new Error("Это не резервная копия keen-pbr-sb")
  }
  return parsed
}

export function downloadBackup(
  bundle: BackupBundle,
  filename = `keen-pbr-sb-backup-${formatDownloadTimestamp()}.json`
): void {
  downloadJson(filename, bundle)
}

function isBackupBundle(value: unknown): value is BackupBundle {
  if (!isRecord(value)) return false
  const { created_at: createdAt, data, format, groups, schema } = value
  if (
    format !== "keen-pbr-sb-backup" ||
    schema !== 1 ||
    typeof createdAt !== "number" ||
    !isRecord(groups) ||
    !isRecord(data)
  ) {
    return false
  }

  return BACKUP_GROUPS.every((group) => typeof groups[group] === "boolean")
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

async function apiJson<T = unknown>(
  url: string,
  init?: RequestInit
): Promise<T> {
  const response = await fetch(url, init)
  const body = (await response.json().catch(() => ({}))) as T & ApiErrorBody
  if (!response.ok) throw new Error(body.error ?? `HTTP ${response.status}`)
  return body
}

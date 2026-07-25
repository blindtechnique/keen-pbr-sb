import { downloadJson, formatDownloadTimestamp } from "@/lib/download"
import { filterNfqwsBackupBundle } from "@/lib/nfqws-backup"

export const BACKUP_GROUPS = [
  "general",
  "transports",
  "outbounds",
  "dns",
  "routing",
  "nfqws_config",
  "nfqws_lists",
] as const

export type BackupGroup = (typeof BACKUP_GROUPS)[number]

export type BackupSelection = Record<BackupGroup, boolean>

export type BackupWireSelection = BackupSelection & {
  /**
   * Compatibility flag for schema-1 archives and older daemons. New daemons
   * use the two explicit nfqws groups and ignore this broader alias.
   */
  nfqws: boolean
}

export type BackupBundle = {
  format: "keen-pbr-sb-backup"
  schema: 1
  created_at: number
  groups: BackupWireSelection
  data: Record<string, unknown>
}

type ApiErrorBody = { error?: string }

export class InvalidBackupBundleError extends Error {
  constructor() {
    super("Это не резервная копия keen-pbr-sb")
    this.name = "InvalidBackupBundleError"
  }
}

export function createDefaultBackupSelection(): BackupSelection {
  return Object.fromEntries(
    BACKUP_GROUPS.map((group) => [group, true])
  ) as BackupSelection
}

export async function createBackup(
  groups: BackupSelection
): Promise<BackupBundle> {
  const backup = await apiJson<unknown>("/api/backup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ groups: toBackupWireSelection(groups) }),
  })
  return filterNfqwsBackupBundle(
    parseBackupBundle(backup),
    groups.nfqws_config,
    groups.nfqws_lists
  )
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
  return parseBackupBundle(JSON.parse(await file.text()))
}

export function downloadBackup(
  bundle: BackupBundle,
  filename = `keen-pbr-sb-backup-${formatDownloadTimestamp()}.json`
): void {
  downloadJson(filename, bundle)
}

export function parseBackupBundle(value: unknown): BackupBundle {
  if (!isRecord(value)) throw new InvalidBackupBundleError()
  const { created_at: createdAt, data, format, groups, schema } = value
  if (
    format !== "keen-pbr-sb-backup" ||
    schema !== 1 ||
    typeof createdAt !== "number" ||
    !isRecord(groups) ||
    !isRecord(data)
  ) {
    throw new InvalidBackupBundleError()
  }

  const commonGroups = ["general", "transports", "outbounds", "dns", "routing"]
  if (commonGroups.some((group) => typeof groups[group] !== "boolean")) {
    throw new InvalidBackupBundleError()
  }
  const legacyNfqws =
    typeof groups.nfqws === "boolean" ? groups.nfqws : undefined
  const hasSplitNfqws =
    typeof groups.nfqws_config === "boolean" ||
    typeof groups.nfqws_lists === "boolean"
  const nfqwsConfig = hasSplitNfqws ? groups.nfqws_config === true : legacyNfqws
  const nfqwsLists = hasSplitNfqws ? groups.nfqws_lists === true : legacyNfqws
  if (nfqwsConfig === undefined || nfqwsLists === undefined) {
    throw new InvalidBackupBundleError()
  }

  const normalizedGroups = {
    general: groups.general as boolean,
    transports: groups.transports as boolean,
    outbounds: groups.outbounds as boolean,
    dns: groups.dns as boolean,
    routing: groups.routing as boolean,
    nfqws_config: nfqwsConfig,
    nfqws_lists: nfqwsLists,
    nfqws: legacyNfqws ?? (nfqwsConfig || nfqwsLists),
  }
  return {
    format: "keen-pbr-sb-backup",
    schema: 1,
    created_at: createdAt,
    groups: normalizedGroups,
    data,
  }
}

export function toBackupWireSelection(
  groups: BackupSelection
): BackupWireSelection {
  return {
    ...groups,
    nfqws: groups.nfqws_config || groups.nfqws_lists,
  }
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

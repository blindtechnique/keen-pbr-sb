import type { LogSettings, LogSettingsRequest } from "@/api/generated/model"

export const LOG_SETTINGS_QUERY_KEY = ["log-settings"] as const
export const DEFAULT_LOG_FILE_BYTES = 1024 * 1024
export const DEFAULT_LOG_MAX_AGE_DAYS = 7
export function logAgeChoices(current: number) {
  return [...new Set([1, 3, 7, 14, 30, 60, 90, 180, 365, current])].sort(
    (left, right) => left - right
  )
}
export const LOG_FILE_SIZE_CHOICES = [
  64 * 1024,
  128 * 1024,
  256 * 1024,
  512 * 1024,
  1024 * 1024,
  2 * 1024 * 1024,
  4 * 1024 * 1024,
  8 * 1024 * 1024,
  16 * 1024 * 1024,
] as const

export function logFileSizeChoices(current: number) {
  return [...new Set<number>([...LOG_FILE_SIZE_CHOICES, current])].sort(
    (left, right) => left - right
  )
}

export function logSizeUnit(bytes: number) {
  return bytes < DEFAULT_LOG_FILE_BYTES
    ? { key: "pages.settings.logging.sizeKiB" as const, size: bytes / 1024 }
    : {
        key: "pages.settings.logging.sizeMiB" as const,
        size: bytes / DEFAULT_LOG_FILE_BYTES,
      }
}

export function updateLogSettingsDraft(
  current: LogSettingsRequest,
  patch: LogSettingsRequest,
  baseline: LogSettingsRequest
): LogSettingsRequest {
  const next = { ...current, ...patch }
  for (const key of Object.keys(next) as (keyof LogSettingsRequest)[]) {
    if (next[key] === baseline[key]) delete next[key]
  }
  return next
}

export async function loadLogSettings(): Promise<LogSettings> {
  const response = await fetch("/api/logs/settings")
  if (!response.ok) throw new Error(`HTTP ${response.status}`)
  return response.json()
}

export async function saveLogSettings(
  patch: LogSettingsRequest
): Promise<LogSettings> {
  const response = await fetch("/api/logs/settings", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(patch),
  })
  const data = await response.json().catch(() => ({}))
  if (!response.ok || data.error || !data.settings) {
    throw new Error(data.error || `HTTP ${response.status}`)
  }
  return data.settings
}

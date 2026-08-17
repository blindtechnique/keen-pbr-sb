import type {
  BackupBundle,
  BackupSelection,
  BackupWireSelection,
} from "@/lib/backup"

export const NFQWS_BACKUP_FORMAT = "keen-pbr-sb-nfqws" as const
export const NFQWS_BACKUP_VERSION = 1 as const

export const NFQWS_BACKUP_CATEGORIES = ["config", "list"] as const

export type NfqwsBackupCategory = (typeof NFQWS_BACKUP_CATEGORIES)[number]
export type NfqwsBackupScope = NfqwsBackupCategory | "all"
export type NfqwsBackupCategoryFiles = Record<string, string>
export type NfqwsBackupFiles = Partial<
  Record<NfqwsBackupCategory, NfqwsBackupCategoryFiles>
>

export type NfqwsBackupBundle = {
  format: typeof NFQWS_BACKUP_FORMAT
  version: typeof NFQWS_BACKUP_VERSION
  files: NfqwsBackupFiles
}

export class InvalidNfqwsBackupError extends Error {
  constructor() {
    super("Invalid nfqws2 backup")
    this.name = "InvalidNfqwsBackupError"
  }
}

export class NfqwsBackupScopeMissingError extends Error {
  constructor() {
    super("The selected nfqws2 backup section is empty")
    this.name = "NfqwsBackupScopeMissingError"
  }
}

export function createNfqwsBackupSelection(
  scope: NfqwsBackupScope
): BackupSelection {
  return {
    general: false,
    transports: false,
    outbounds: false,
    dns: false,
    routing: false,
    nfqws_config: scope !== "list",
    nfqws_lists: scope !== "config",
  }
}

export function selectNfqwsBackupBundle(
  bundle: BackupBundle,
  scope: NfqwsBackupScope
): BackupBundle {
  const selection = createNfqwsBackupSelection(scope)
  const filtered = filterNfqwsBackupBundle(
    bundle,
    selection.nfqws_config,
    selection.nfqws_lists
  )
  const nfqwsFiles = filtered.data.nfqws
  if (!isRecord(nfqwsFiles)) throw new InvalidNfqwsBackupError()

  if (Object.keys(nfqwsFiles).length === 0) {
    throw new NfqwsBackupScopeMissingError()
  }

  return {
    ...filtered,
    groups: {
      ...filtered.groups,
      general: false,
      transports: false,
      outbounds: false,
      dns: false,
      routing: false,
    },
    data: {
      nfqws: nfqwsFiles,
    },
  }
}

export function filterNfqwsBackupBundle(
  bundle: BackupBundle,
  includeConfig: boolean,
  includeLists: boolean
): BackupBundle {
  const data = { ...bundle.data }
  const nfqwsFiles = data.nfqws

  if (!includeConfig && !includeLists) {
    delete data.nfqws
  } else if (nfqwsFiles !== undefined) {
    if (!isRecord(nfqwsFiles)) throw new InvalidNfqwsBackupError()

    data.nfqws = Object.fromEntries(
      Object.entries(nfqwsFiles).filter(([path]) => {
        const category = classifyNfqwsBackupPath(path)
        return category === "config" ? includeConfig : includeLists
      })
    )
  }

  const groups: BackupWireSelection = {
    ...bundle.groups,
    nfqws_config: includeConfig,
    nfqws_lists: includeLists,
    nfqws: includeConfig || includeLists,
  }

  return {
    ...bundle,
    groups,
    data,
  }
}

export function parseNfqwsBackupBundle(value: unknown): NfqwsBackupBundle {
  if (!isRecord(value)) throw new InvalidNfqwsBackupError()
  if (
    value.format !== NFQWS_BACKUP_FORMAT ||
    value.version !== NFQWS_BACKUP_VERSION ||
    !isRecord(value.files)
  ) {
    throw new InvalidNfqwsBackupError()
  }

  const files: NfqwsBackupFiles = {}
  for (const category of NFQWS_BACKUP_CATEGORIES) {
    const categoryFiles = value.files[category]
    if (categoryFiles === undefined) continue
    files[category] = parseCategoryFiles(categoryFiles, category)
  }

  if (!hasNfqwsBackupFiles(files)) throw new InvalidNfqwsBackupError()

  return {
    format: NFQWS_BACKUP_FORMAT,
    version: NFQWS_BACKUP_VERSION,
    files,
  }
}

export function selectNfqwsBackupFiles(
  files: NfqwsBackupFiles,
  scope: NfqwsBackupScope
): NfqwsBackupFiles {
  const selected: NfqwsBackupFiles = {}
  const categories =
    scope === "all" ? NFQWS_BACKUP_CATEGORIES : ([scope] as const)

  for (const category of categories) {
    const categoryFiles = files[category]
    if (categoryFiles && Object.keys(categoryFiles).length > 0) {
      selected[category] = { ...categoryFiles }
    }
  }

  return selected
}

export function hasNfqwsBackupFiles(files: NfqwsBackupFiles): boolean {
  return NFQWS_BACKUP_CATEGORIES.some(
    (category) => Object.keys(files[category] ?? {}).length > 0
  )
}

function parseCategoryFiles(
  value: unknown,
  category?: NfqwsBackupCategory
): NfqwsBackupCategoryFiles {
  if (!isRecord(value)) throw new InvalidNfqwsBackupError()

  const entries = Object.entries(value)
  if (
    entries.some(
      ([name, content]) =>
        typeof content !== "string" ||
        (category !== undefined && !isValidLegacyNfqwsName(category, name))
    )
  ) {
    throw new InvalidNfqwsBackupError()
  }

  return Object.fromEntries(entries) as NfqwsBackupCategoryFiles
}

export function classifyNfqwsBackupPath(path: string): NfqwsBackupCategory {
  if (
    path.length === 0 ||
    path.length > 512 ||
    path.includes("\\") ||
    path.startsWith("/") ||
    path.endsWith("/")
  ) {
    throw new InvalidNfqwsBackupError()
  }

  const parts = path.split("/")
  if (
    parts.length < 2 ||
    parts.some((part) => part.length === 0 || part === "." || part === "..")
  ) {
    throw new InvalidNfqwsBackupError()
  }

  const [root] = parts
  const filename = parts.at(-1) ?? ""
  if (root === "strategies" && filename.endsWith(".conf")) return "config"
  if (root !== "nfqws2") throw new InvalidNfqwsBackupError()
  if (filename.endsWith(".list")) return "list"
  if (
    filename.endsWith(".conf") ||
    filename.endsWith(".lua") ||
    filename.endsWith(".lua.gz")
  ) {
    return "config"
  }

  throw new InvalidNfqwsBackupError()
}

function isValidLegacyNfqwsName(
  category: NfqwsBackupCategory,
  name: string
): boolean {
  if (
    name.length === 0 ||
    name.length > 80 ||
    name === "." ||
    name === ".." ||
    !/^[A-Za-z0-9_.()-]+$/.test(name)
  ) {
    return false
  }
  return category === "config" ? name.endsWith(".conf") : name.endsWith(".list")
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

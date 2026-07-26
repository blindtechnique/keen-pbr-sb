type ReadableStorage = Pick<Storage, "getItem">
type WritableStorage = Pick<Storage, "setItem">

export function safeStorageGet(
  storage: () => ReadableStorage,
  key: string
): string | null {
  try {
    return storage().getItem(key)
  } catch {
    return null
  }
}

export function safeStorageSet(
  storage: () => WritableStorage,
  key: string,
  value: string
): boolean {
  try {
    storage().setItem(key, value)
    return true
  } catch {
    return false
  }
}

export function safeStorageMatches(
  storage: () => Storage,
  candidate: Storage | null
): boolean {
  try {
    return candidate === storage()
  } catch {
    return false
  }
}

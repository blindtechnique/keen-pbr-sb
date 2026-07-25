import type { ConfigObject } from "@/api/generated/model/configObject"
import type { ListConfig } from "@/api/generated/model/listConfig"

export function getListDisplayName(
  technicalId: string,
  lists: ConfigObject["lists"]
): string {
  return lists?.[technicalId]?.display_name?.trim() || technicalId
}

export function getListSearchText(
  technicalId: string,
  lists: ConfigObject["lists"]
): string {
  const displayName = getListDisplayName(technicalId, lists)
  return displayName === technicalId
    ? technicalId
    : `${displayName}\n${technicalId}`
}

export function getListReferenceLabel(
  technicalId: string,
  lists: ConfigObject["lists"]
): string {
  const displayName = getListDisplayName(technicalId, lists)
  return displayName === technicalId
    ? technicalId
    : `${displayName} (${technicalId})`
}

export function formatListReferenceLabels(
  technicalIds: readonly string[],
  lists: ConfigObject["lists"]
): string {
  return technicalIds
    .map((technicalId) => getListReferenceLabel(technicalId, lists))
    .join(", ")
}

export function sortListIdsByDisplayName(
  technicalIds: string[],
  lists: ConfigObject["lists"]
): string[] {
  return [...technicalIds].sort((left, right) => {
    const byDisplayName = getListDisplayName(left, lists).localeCompare(
      getListDisplayName(right, lists)
    )
    return byDisplayName || left.localeCompare(right)
  })
}

export function withListDisplayName(
  list: ListConfig,
  displayName: string
): ListConfig {
  const normalizedDisplayName = displayName.trim()
  const listWithoutDisplayName = { ...list }
  delete listWithoutDisplayName.display_name
  return normalizedDisplayName
    ? { ...listWithoutDisplayName, display_name: normalizedDisplayName }
    : listWithoutDisplayName
}

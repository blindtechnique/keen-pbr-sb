import { useMemo, useState } from "react"

export function pruneSelectedIds(
  selectedIds: Iterable<string>,
  rowIds: Iterable<string>
) {
  const validIds = new Set(rowIds)
  const next = new Set<string>()

  for (const id of selectedIds) {
    if (validIds.has(id)) {
      next.add(id)
    }
  }

  return next
}

export function toggleSelectedId(
  selectedIds: Iterable<string>,
  rowIds: Iterable<string>,
  rowId: string
) {
  const next = pruneSelectedIds(selectedIds, rowIds)

  if (next.has(rowId)) {
    next.delete(rowId)
  } else {
    next.add(rowId)
  }

  return next
}

export function selectVisibleIds(rowIds: Iterable<string>, selected: boolean) {
  return selected ? new Set(rowIds) : new Set<string>()
}

export function useRowSelection(rowIds: string[]) {
  const [selectedIdsRaw, setSelectedIdsRaw] = useState<Set<string>>(
    () => new Set()
  )
  const selectedIds = useMemo(
    () => pruneSelectedIds(selectedIdsRaw, rowIds),
    [selectedIdsRaw, rowIds]
  )

  return {
    selectedIds,
    selectedCount: selectedIds.size,
    hasSelection: selectedIds.size > 0,
    toggleOne: (rowId: string) => {
      setSelectedIdsRaw((previous) => toggleSelectedId(previous, rowIds, rowId))
    },
    // Scope matters: a page can render several tables over one selection, as
    // outbounds do with their groups. Without the explicit list, ticking the
    // header box in one group selected every row on the page.
    setAllVisible: (selected: boolean, scopedRowIds?: Iterable<string>) => {
      const scope = scopedRowIds ? [...scopedRowIds] : rowIds
      setSelectedIdsRaw((previous) => {
        const next = pruneSelectedIds(previous, rowIds)
        for (const id of scope) {
          if (selected) {
            next.add(id)
          } else {
            next.delete(id)
          }
        }
        return next
      })
    },
    clear: () => {
      setSelectedIdsRaw(new Set())
    },
  }
}

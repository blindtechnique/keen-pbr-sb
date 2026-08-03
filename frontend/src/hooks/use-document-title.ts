import { useEffect } from "react"

// KeeneticOS names the browser tab after the open section, e.g.
// "SDD's Netcraze Ultra (NC-1812) – Маршрутизация". Ours read "keen-pbr-sb" on
// every one of the eleven pages, so a bookmark lost the section and several
// open tabs of the panel were indistinguishable from one another.
export const APP_NAME = "keen-pbr-sb"

export function documentTitleFor(section: string | undefined): string {
  const trimmed = section?.trim()
  return trimmed ? `${trimmed} — ${APP_NAME}` : APP_NAME
}

export function useDocumentTitle(section: string | undefined): void {
  useEffect(() => {
    document.title = documentTitleFor(section)
    // Restoring the bare product name on unmount keeps the tab honest for the
    // moment between routes, and for screens that set no title at all.
    return () => {
      document.title = APP_NAME
    }
  }, [section])
}

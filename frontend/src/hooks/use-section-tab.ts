import { useCallback, useEffect, useState } from "react"

function hashValue() {
  return decodeURIComponent(window.location.hash.replace(/^#/, ""))
}

export function useSectionTab<T extends string>(
  validTabs: readonly T[],
  defaultTab: T
) {
  const [requestedTab, setRequestedTab] = useState<T>(
    () => (hashValue() || defaultTab) as T
  )
  const activeTab = validTabs.includes(requestedTab)
    ? requestedTab
    : defaultTab

  useEffect(() => {
    const handleHashChange = () => {
      setRequestedTab((hashValue() || defaultTab) as T)
    }

    window.addEventListener("hashchange", handleHashChange)
    return () => window.removeEventListener("hashchange", handleHashChange)
  }, [defaultTab])

  const setActiveTab = useCallback((nextTab: T) => {
    setRequestedTab(nextTab)
    const url = new URL(window.location.href)
    url.hash = nextTab
    window.history.replaceState(window.history.state, "", url)
  }, [])

  return [activeTab, setActiveTab] as const
}

import { useInfiniteQuery } from "@tanstack/react-query"
import { ChevronRightIcon } from "lucide-react"
import { useDeferredValue, useMemo, useState } from "react"
import { useTranslation } from "react-i18next"

import { queryConnections } from "@/api/generated/keen-api"
import type { ConnectionRecord } from "@/api/generated/model/connectionRecord"
import { PageHeader } from "@/components/shared/page-header"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
import { Label } from "@/components/ui/label"
import { cn } from "@/lib/utils"

type DeviceGroup = {
  key: string
  name: string
  address: string
  connections: ConnectionRecord[]
  activeCount: number
  lastSeen: number
}

export function ConnectionsPage() {
  const { t } = useTranslation()
  const [filter, setFilter] = useState("")
  const deferredFilter = useDeferredValue(filter.trim())
  const [activeOnly, setActiveOnly] = useState(true)
  const [expanded, setExpanded] = useState<Set<string>>(new Set())

  const query = useInfiniteQuery({
    queryKey: [
      "connections",
      activeOnly ? "active" : "all",
      deferredFilter,
    ],
    initialPageParam: undefined as string | undefined,
    queryFn: async ({ pageParam }) => {
      const response = await queryConnections({
        active_only: activeOnly,
        cursor: pageParam,
        limit: 100,
        search: deferredFilter || undefined,
        sort: "last_seen",
        order: "desc",
      })
      if (response.status !== 200) {
        throw new Error(response.data.error)
      }
      return response.data
    },
    getNextPageParam: (lastPage) => lastPage.next_cursor,
    refetchInterval: (currentQuery) =>
      currentQuery.state.data?.pages.length === 1 ? 3_000 : false,
    refetchIntervalInBackground: false,
  })

  const connections = useMemo(
    () => query.data?.pages.flatMap((page) => page.items) ?? [],
    [query.data]
  )
  const groups = useMemo(() => {
    // One row per device, like the firmware does, so a busy host does not bury
    // everything else under hundreds of sessions.
    const byDevice = new Map<string, DeviceGroup>()
    for (const item of connections) {
      const key = item.source
      const group = byDevice.get(key) ?? {
        key,
        name: item.device || item.source,
        address: item.source,
        connections: [],
        activeCount: 0,
        lastSeen: 0,
      }
      group.connections.push(item)
      if (item.active) group.activeCount += 1
      group.lastSeen = Math.max(group.lastSeen, item.last_seen)
      byDevice.set(key, group)
    }

    return [...byDevice.values()]
      .map((group) => ({
        ...group,
        connections: group.connections.sort((a, b) => b.last_seen - a.last_seen),
      }))
      .sort((a, b) => b.connections.length - a.connections.length)
  }, [connections])

  const totalConnections = query.data?.pages[0]?.total ?? connections.length

  const toggle = (key: string) => {
    setExpanded((current) => {
      const next = new Set(current)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }

  return (
    <div className="space-y-3">
      <PageHeader
        description={t("connections.description")}
        title={t("connections.title")}
      />

      <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
        <Input
          className="sm:max-w-md"
          onChange={(event) => setFilter(event.target.value)}
          placeholder={t("connections.filter")}
          value={filter}
        />
        <div className="flex items-center gap-2">
          <Switch
            checked={activeOnly}
            id="active-only"
            onCheckedChange={setActiveOnly}
          />
          <Label htmlFor="active-only">{t("connections.activeOnly")}</Label>
        </div>
        <div className="flex items-center gap-2 sm:ml-auto">
          <Badge variant="secondary">
            {t("connections.deviceCount", { count: groups.length })}
          </Badge>
          <Badge variant="secondary">{totalConnections}</Badge>
        </div>
      </div>

      <div className="divide-y border-y">
        {groups.map((group) => {
          const isOpen = expanded.has(group.key)

          return (
            <div key={group.key}>
              <button
                aria-expanded={isOpen}
                className="flex w-full items-center gap-3 py-2.5 text-left hover:bg-muted/40"
                onClick={() => toggle(group.key)}
                type="button"
              >
                <ChevronRightIcon
                  className={cn(
                    "size-4 shrink-0 text-muted-foreground transition-transform",
                    isOpen && "rotate-90"
                  )}
                />
                <div className="min-w-0 flex-1">
                  <div className="truncate font-medium">{group.name}</div>
                  <div className="truncate font-mono text-xs text-muted-foreground">
                    {group.address}
                  </div>
                </div>
                <div className="flex shrink-0 flex-wrap items-center justify-end gap-1.5">
                  <Badge size="xs" variant="secondary">
                    {group.connections.length}
                  </Badge>
                </div>
              </button>

              {isOpen ? (
                <div className="space-y-1 pb-3 pl-7">
                  {group.connections.map((item) => (
                    <SessionRow item={item} key={item.id} t={t} />
                  ))}
                </div>
              ) : null}
            </div>
          )
        })}

        {groups.length === 0 ? (
          <p className="py-6 text-center text-sm text-muted-foreground">
            {t("connections.empty")}
          </p>
        ) : null}
      </div>

      {query.hasNextPage ? (
        <div className="flex justify-center">
          <Button
            disabled={query.isFetchingNextPage}
            onClick={() => void query.fetchNextPage()}
            variant="outline"
          >
            {query.isFetchingNextPage
              ? t("connections.loadingMore")
              : t("connections.loadMore", {
                  loaded: connections.length,
                  total: totalConnections,
                })}
          </Button>
        </div>
      ) : null}
    </div>
  )
}

function SessionRow({
  item,
  t,
}: {
  item: ConnectionRecord
  t: (key: string, options?: Record<string, unknown>) => string
}) {
  const [primaryDomain, ...otherDomains] = item.destination_domains

  return (
    <div className="connection-session-row grid grid-cols-1 gap-x-3 gap-y-0.5 py-1 text-sm sm:grid-cols-[minmax(0,1fr)_auto]">
      <div className="min-w-0">
        {primaryDomain ? (
          <div className="truncate">{primaryDomain}</div>
        ) : null}
        <div className="truncate font-mono text-xs text-muted-foreground">
          {item.destination}:{item.destination_port}
        </div>
        {otherDomains.length > 0 ? (
          <div
            className="truncate text-xs text-muted-foreground"
            title={otherDomains.join(", ")}
          >
            {otherDomains.join(", ")}
          </div>
        ) : null}
      </div>
      <div className="flex flex-wrap items-center gap-1.5 sm:justify-end">
        <span
          className="text-xs tabular-nums text-muted-foreground"
          title={new Date(item.last_seen * 1000).toLocaleString()}
        >
          {item.active
            ? t("connections.age.live")
            : formatLastSeen(item.last_seen, t)}
        </span>
        <span className="text-xs text-muted-foreground">
          {item.protocol.toUpperCase()}
        </span>
        <Badge size="xs" variant={item.active ? "success" : "secondary"}>
          {item.state}
        </Badge>
      </div>
    </div>
  )
}

/**
 * Only closed connections get an age. While one is live the age is always
 * "a moment ago" and says nothing, so the word "active" carries more.
 */
function formatLastSeen(
  lastSeen: number,
  t: (key: string, options?: Record<string, unknown>) => string
): string {
  if (!lastSeen) {
    return ""
  }
  const seconds = Math.max(0, Math.floor(Date.now() / 1000) - lastSeen)
  if (seconds < 10) {
    return t("connections.age.now")
  }
  if (seconds < 60) {
    return t("connections.age.seconds", { count: seconds })
  }
  if (seconds < 3600) {
    return t("connections.age.minutes", { count: Math.floor(seconds / 60) })
  }
  return t("connections.age.hours", { count: Math.floor(seconds / 3600) })
}

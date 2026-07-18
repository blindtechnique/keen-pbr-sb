import { useQuery } from "@tanstack/react-query"
import { useMemo, useState } from "react"
import { useTranslation } from "react-i18next"

import { PageHeader } from "@/components/shared/page-header"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
import { Label } from "@/components/ui/label"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"

type Connection = {
  id: string; protocol: string; state: string; source: string; source_port: number
  destination: string; destination_port: number; route: string; device: string; active: boolean; last_seen: number
}

export function ConnectionsPage() {
  const { t } = useTranslation()
  const [filter, setFilter] = useState("")
  const [activeOnly, setActiveOnly] = useState(true)
  const [sort, setSort] = useState<"recent" | "source" | "destination" | "route">("recent")
  const query = useQuery({
    queryKey: ["connections"],
    queryFn: async () => {
      const response = await fetch("/api/connections")
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      return response.json() as Promise<Connection[]>
    },
    refetchInterval: 3_000,
  })
  const rows = useMemo(() => {
    const needle = filter.trim().toLowerCase()
    return (query.data ?? [])
      .filter((item) => !activeOnly || item.active)
      .filter((item) => !needle || `${item.source} ${item.destination} ${item.route} ${item.state} ${item.protocol}`.toLowerCase().includes(needle))
      .sort((a, b) => sort === "recent" ? b.last_seen - a.last_seen :
        sort === "source" ? a.source.localeCompare(b.source) :
        sort === "destination" ? a.destination.localeCompare(b.destination) :
        a.route.localeCompare(b.route))
  }, [activeOnly, filter, query.data, sort])

  return <div className="space-y-6">
    <PageHeader title={t("connections.title")} description={t("connections.description")} />
    <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
      <Input className="max-w-md" value={filter} onChange={(event) => setFilter(event.target.value)} placeholder={t("connections.filter")} />
      <div className="flex items-center gap-2"><Switch id="active-only" checked={activeOnly} onCheckedChange={setActiveOnly} /><Label htmlFor="active-only">{t("connections.activeOnly")}</Label></div>
      <select className="h-9 rounded-md border bg-background px-3" value={sort} onChange={(event) => setSort(event.target.value as typeof sort)} aria-label={t("connections.sort")}>
        <option value="recent">{t("connections.sortRecent")}</option><option value="source">{t("connections.sortSource")}</option>
        <option value="destination">{t("connections.sortDestination")}</option><option value="route">{t("connections.sortRoute")}</option>
      </select>
      <Badge variant="secondary">{rows.length}</Badge>
    </div>
    <div className="rounded-md border">
      <Table><TableHeader><TableRow>
        <TableHead>{t("connections.state")}</TableHead><TableHead>{t("connections.device")}</TableHead>
        <TableHead>{t("connections.destination")}</TableHead><TableHead>{t("connections.protocol")}</TableHead><TableHead>{t("connections.route")}</TableHead>
      </TableRow></TableHeader><TableBody>
        {rows.map((item) => <TableRow key={item.id}>
          <TableCell><Badge variant={item.active ? "default" : "secondary"}>{item.state}</Badge></TableCell>
          <TableCell><div>{item.device || item.source}</div><div className="font-mono text-xs text-muted-foreground">{item.source}:{item.source_port}</div></TableCell>
          <TableCell className="font-mono text-xs">{item.destination}:{item.destination_port}</TableCell>
          <TableCell>{item.protocol.toUpperCase()}</TableCell><TableCell>{item.route}</TableCell>
        </TableRow>)}
      </TableBody></Table>
    </div>
  </div>
}

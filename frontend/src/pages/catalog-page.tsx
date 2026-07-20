import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { useMemo, useState } from "react"
import { CheckIcon, RefreshCw } from "lucide-react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"

import type { ApiError } from "@/api/client"
import type { ConfigObject } from "@/api/generated/model/configObject"
import type { ListConfig } from "@/api/generated/model/listConfig"
import type { RouteRule } from "@/api/generated/model/routeRule"
import { useConfigMutationPending, usePostConfigMutation } from "@/api/mutations"
import { useGetConfig } from "@/api/queries"
import { selectConfig } from "@/api/selectors"
import { PageHeader } from "@/components/shared/page-header"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import { getApiErrorMessage } from "@/lib/api-errors"
import { cn } from "@/lib/utils"

/**
 * Ready-made lists borrowed from the awg-manager catalogue.
 *
 * The upstream file is the source of truth, so this page renders whatever it
 * currently contains rather than a curated copy - the copy we kept by hand
 * went stale within days.
 */
type Preset = {
  id: string
  name: string
  category?: string
  engines?: {
    dns?: { domains?: string[] }
    singbox?: {
      action?: string
      ruleSets?: { tag?: string; url?: string }[]
    }
  }
}

type CatalogResponse = {
  source?: string
  updated_at?: number
  presets?: Preset[]
  url?: string
  detour?: string
  error?: string
}

const CATEGORY_ORDER = [
  "ai",
  "social",
  "media",
  "developer",
  "cloud",
  "gaming",
  "block",
]

const DIRECT = "__direct__"

export function CatalogPage() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()

  const configQuery = useGetConfig()
  const config = selectConfig(configQuery.data)
  const postConfigMutation = usePostConfigMutation()
  const configMutationPending = useConfigMutationPending()

  const catalogQuery = useQuery<CatalogResponse>({
    queryKey: ["catalog"],
    queryFn: async () => {
      const response = await fetch("/api/catalog")
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      return response.json()
    },
  })

  const [category, setCategory] = useState("all")
  const [search, setSearch] = useState("")
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [destination, setDestination] = useState("")
  const [sourceDetour, setSourceDetour] = useState<string | null>(null)

  // Only outbounds that can actually carry traffic: urltest groups and
  // interfaces both qualify, blackhole does not.
  const outboundTags = useMemo(
    () =>
      (config?.outbounds ?? [])
        .filter((outbound) => outbound.type !== "blackhole")
        .map((outbound) => outbound.tag),
    [config]
  )

  const effectiveDestination = destination || outboundTags[0] || ""
  const effectiveSourceDetour = sourceDetour ?? catalogQuery.data?.detour ?? ""

  const refreshMutation = useMutation({
    mutationFn: async () => {
      const response = await fetch("/api/catalog/refresh", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ detour: effectiveSourceDetour }),
      })
      const data = await response.json().catch(() => ({}))
      if (!response.ok || data.error) {
        throw new Error(data.error || `HTTP ${response.status}`)
      }
      return data as { updated?: boolean }
    },
    onSuccess: async (data) => {
      await queryClient.invalidateQueries({ queryKey: ["catalog"] })
      toast.success(
        data.updated
          ? t("pages.catalog.refreshed")
          : t("pages.catalog.refreshFailed")
      )
    },
    onError: (error: Error) => toast.error(error.message, { richColors: true }),
  })

  const presets = catalogQuery.data?.presets ?? []
  const existingNames = new Set(Object.keys(config?.lists ?? {}))

  const visible = useMemo(() => {
    const needle = search.trim().toLowerCase()
    return presets.filter(
      (preset) =>
        (category === "all" || preset.category === category) &&
        (needle === "" || preset.name.toLowerCase().includes(needle))
    )
  }, [presets, category, search])

  const categories = useMemo(() => {
    const present = new Set(presets.map((preset) => preset.category))
    return CATEGORY_ORDER.filter((key) => present.has(key))
  }, [presets])

  const toggle = (id: string) => {
    setSelected((previous) => {
      const next = new Set(previous)
      if (next.has(id)) {
        next.delete(id)
      } else {
        next.add(id)
      }
      return next
    })
  }

  const handleAdd = () => {
    if (!config || selected.size === 0) {
      return
    }

    const nextConfig: ConfigObject = {
      ...config,
      lists: { ...(config.lists ?? {}) },
      route: { ...(config.route ?? {}), rules: [...(config.route?.rules ?? [])] },
    }

    const added: string[] = []

    for (const preset of presets) {
      if (!selected.has(preset.id)) {
        continue
      }

      const name = listNameFor(preset.id, nextConfig.lists ?? {})
      const url = preset.engines?.singbox?.ruleSets?.[0]?.url
      const domains = preset.engines?.dns?.domains

      // A preset carries either a compiled rule set or a plain domain list;
      // taking the URL when present keeps the entry small and updatable.
      const entry: ListConfig = url
        ? { url, ...(effectiveSourceDetour ? { detour: effectiveSourceDetour } : {}) }
        : { domains: domains ?? [] }

      if (!url && (!domains || domains.length === 0)) {
        continue
      }

      nextConfig.lists![name] = entry
      added.push(name)
    }

    if (added.length === 0) {
      return
    }

    if (effectiveDestination === DIRECT) {
      // Nothing to route: a list with no rule simply stays unused, which is
      // what "leave it on the direct connection" means here.
    } else if (effectiveDestination) {
      const rule: RouteRule = {
        list: added,
        outbound: effectiveDestination,
      }
      nextConfig.route!.rules = [...(nextConfig.route!.rules ?? []), rule]
    }

    postConfigMutation.mutate(
      { data: nextConfig },
      {
        onSuccess: () => {
          setSelected(new Set())
          toast.success(t("pages.catalog.added", { count: added.length }))
        },
        onError: (error) =>
          toast.error(getApiErrorMessage(error as ApiError), {
            richColors: true,
          }),
      }
    )
  }

  return (
    <div className="space-y-3">
      <PageHeader
        description={t("pages.catalog.description")}
        title={t("pages.catalog.title")}
      />

      <div className="flex flex-wrap items-center justify-between gap-3 rounded-md border bg-muted px-3 py-2">
        <p className="text-[13px] text-muted-foreground">
          {t("pages.catalog.source")}{" "}
          <a
            className="text-primary hover:underline"
            href="https://github.com/hoaxisr/awg-manager"
            rel="noreferrer"
            target="_blank"
          >
            hoaxisr/awg-manager
          </a>
          {catalogQuery.data?.updated_at
            ? ` · ${t("pages.catalog.updatedAt", {
                date: new Date(
                  catalogQuery.data.updated_at * 1000
                ).toLocaleDateString(),
              })}`
            : null}
          {presets.length > 0
            ? ` · ${t("pages.catalog.count", { count: presets.length })}`
            : null}
        </p>

        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[13px]">{t("pages.catalog.downloadVia")}</span>
          <select
            className="h-8 rounded-md border border-input bg-card px-2 text-[13px]"
            onChange={(event) => setSourceDetour(event.target.value)}
            value={effectiveSourceDetour}
          >
            <option value="">{t("pages.catalog.directly")}</option>
            {outboundTags.map((tag) => (
              <option key={tag} value={tag}>
                {tag}
              </option>
            ))}
          </select>
          <Button
            disabled={refreshMutation.isPending}
            onClick={() => refreshMutation.mutate()}
            size="sm"
            variant="outline"
          >
            <RefreshCw
              className={cn(
                "mr-1 h-4 w-4",
                refreshMutation.isPending && "animate-spin"
              )}
            />
            {t("pages.catalog.checkNow")}
          </Button>
        </div>
      </div>

      <div className="flex flex-wrap gap-1.5">
        <CategoryChip
          active={category === "all"}
          label={t("pages.catalog.categories.all")}
          onClick={() => setCategory("all")}
        />
        {categories.map((key) => (
          <CategoryChip
            active={category === key}
            key={key}
            label={t(`pages.catalog.categories.${key}`)}
            onClick={() => setCategory(key)}
          />
        ))}
      </div>

      <Input
        onChange={(event) => setSearch(event.target.value)}
        placeholder={t("pages.catalog.searchPlaceholder")}
        value={search}
      />

      {catalogQuery.isLoading ? (
        <div className="space-y-2">
          {[0, 1, 2, 3, 4].map((index) => (
            <Skeleton className="h-10 w-full" key={index} />
          ))}
        </div>
      ) : null}

      {!catalogQuery.isLoading && visible.length === 0 ? (
        <p className="py-8 text-center text-sm text-muted-foreground">
          {t("pages.catalog.empty")}
        </p>
      ) : null}

      <div className="divide-y border-y">
        {visible.map((preset) => {
          const url = preset.engines?.singbox?.ruleSets?.[0]?.url
          const domains = preset.engines?.dns?.domains?.length ?? 0
          const blocks = preset.engines?.singbox?.action === "reject"
          const already = existingNames.has(sanitize(preset.id))

          return (
            <label
              className="flex cursor-pointer items-center gap-3 px-3 py-2.5 text-sm hover:bg-secondary"
              key={preset.id}
            >
              <input
                checked={selected.has(preset.id)}
                className="size-4 accent-[var(--primary)]"
                disabled={already}
                onChange={() => toggle(preset.id)}
                type="checkbox"
              />
              <span className="min-w-0 flex-1 truncate">{preset.name}</span>
              <span className="shrink-0 text-xs text-muted-foreground">
                {url
                  ? t("pages.catalog.ruleSet")
                  : t("pages.catalog.domains", { count: domains })}
              </span>
              {already ? (
                <span className="flex shrink-0 items-center gap-1 text-xs text-success">
                  <CheckIcon className="size-3.5" />
                  {t("pages.catalog.alreadyAdded")}
                </span>
              ) : (
                <span
                  className={cn(
                    "shrink-0 rounded-full px-2 py-0.5 text-xs",
                    blocks
                      ? "bg-destructive/10 text-destructive"
                      : "bg-success/10 text-success"
                  )}
                >
                  {blocks
                    ? t("pages.catalog.actionBlock")
                    : t("pages.catalog.actionTunnel")}
                </span>
              )}
            </label>
          )
        })}
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3 border-t pt-3">
        <span className="text-[13px] text-muted-foreground">
          {t("pages.catalog.selected", { count: selected.size })}
        </span>
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[13px]">{t("pages.catalog.routeTo")}</span>
          <select
            className="h-9 rounded-md border border-input bg-card px-2 text-[13px]"
            onChange={(event) => setDestination(event.target.value)}
            value={effectiveDestination}
          >
            {outboundTags.map((tag) => (
              <option key={tag} value={tag}>
                {tag}
              </option>
            ))}
            <option value={DIRECT}>{t("pages.catalog.directly")}</option>
          </select>
          <Button
            disabled={selected.size === 0 || configMutationPending}
            onClick={handleAdd}
          >
            {t("pages.catalog.add")}
          </Button>
        </div>
      </div>
    </div>
  )
}

function CategoryChip({
  active,
  label,
  onClick,
}: {
  active: boolean
  label: string
  onClick: () => void
}) {
  return (
    <button
      className={cn(
        "rounded-full border px-3 py-1 text-[13px]",
        active
          ? "border-primary bg-accent text-primary"
          : "border-border text-foreground hover:bg-secondary"
      )}
      onClick={onClick}
      type="button"
    >
      {label}
    </button>
  )
}

// List names are restricted to ^[a-z][a-z0-9_]*$ and 24 characters, which the
// catalogue ids do not always satisfy.
function sanitize(id: string): string {
  const cleaned = id
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
  const prefixed = /^[a-z]/.test(cleaned) ? cleaned : `l_${cleaned}`
  return prefixed.slice(0, 24)
}

function listNameFor(id: string, existing: Record<string, unknown>): string {
  const base = sanitize(id)
  if (!(base in existing)) {
    return base
  }
  for (let suffix = 2; suffix < 100; suffix += 1) {
    const candidate = `${base.slice(0, 21)}_${suffix}`
    if (!(candidate in existing)) {
      return candidate
    }
  }
  return base
}

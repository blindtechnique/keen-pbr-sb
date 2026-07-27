import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { useMemo, useState } from "react"
import { CheckIcon, RefreshCw } from "lucide-react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"

import type { ApiError } from "@/api/client"
import {
  useConfigMutationPending,
  usePostConfigMutation,
} from "@/api/mutations"
import { useGetConfig } from "@/api/queries"
import { selectConfig } from "@/api/selectors"
import { BottomActionBar } from "@/components/shared/bottom-action-bar"
import { PageHeader } from "@/components/shared/page-header"
import { SectionTabs, type SectionTab } from "@/components/shared/section-tabs"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Skeleton } from "@/components/ui/skeleton"
import { useSectionTab } from "@/hooks/use-section-tab"
import { getApiErrorMessage } from "@/lib/api-errors"
import {
  createOutboundDisplayNameMap,
} from "@/lib/outbound-display"
import { cn } from "@/lib/utils"
import {
  applyCatalogAddDraft,
  createCatalogAddDraft,
  sanitizeCatalogListId,
  type CatalogAddDraft,
  type CatalogPreset,
} from "@/pages/catalog-add"

/**
 * Ready-made lists borrowed from the awg-manager catalogue.
 *
 * The upstream file is the source of truth, so this page renders whatever it
 * currently contains rather than a curated copy - the copy we kept by hand
 * went stale within days.
 */
type CatalogResponse = {
  source?: string
  updated_at?: number
  presets?: CatalogPreset[]
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
const EMPTY_PRESETS: readonly CatalogPreset[] = []

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

  const [search, setSearch] = useState("")
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [destination, setDestination] = useState("")
  const [sourceDetour, setSourceDetour] = useState<string | null>(null)
  const [addDraft, setAddDraft] = useState<CatalogAddDraft | null>(null)

  // Only outbounds that can actually carry traffic: urltest groups and
  // interfaces both qualify, blackhole does not.
  const outboundTags = useMemo(
    () =>
      (config?.outbounds ?? [])
        .filter((outbound) => outbound.type !== "blackhole")
        .map((outbound) => outbound.tag),
    [config]
  )
  const outboundDisplayNames = useMemo(
    () => createOutboundDisplayNameMap(config?.outbounds ?? []),
    [config?.outbounds]
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

  const presets = catalogQuery.data?.presets ?? EMPTY_PRESETS
  const existingNames = new Set(Object.keys(config?.lists ?? {}))

  const categories = useMemo(() => {
    const present = new Set(presets.map((preset) => preset.category))
    return CATEGORY_ORDER.filter((key) => present.has(key))
  }, [presets])

  const categoryTabs = useMemo<SectionTab<string>[]>(() => {
    const counts = new Map<string, number>()
    for (const preset of presets) {
      if (preset.category) {
        counts.set(preset.category, (counts.get(preset.category) ?? 0) + 1)
      }
    }

    return [
      {
        value: "all",
        label: t("pages.catalog.categories.all"),
        count: presets.length,
      },
      ...categories.map((key) => ({
        value: key,
        label: t(`pages.catalog.categories.${key}`),
        count: counts.get(key) ?? 0,
      })),
    ]
  }, [categories, presets, t])
  const [category, setCategory] = useSectionTab(
    categoryTabs.map((tab) => tab.value),
    "all"
  )

  const visible = useMemo(() => {
    const needle = search.trim().toLowerCase()
    return presets.filter(
      (preset) =>
        (category === "all" || preset.category === category) &&
        (needle === "" || preset.name.toLowerCase().includes(needle))
    )
  }, [presets, category, search])

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

  const openAddDialog = () => {
    if (!config || selected.size === 0) {
      return
    }

    setAddDraft(
      createCatalogAddDraft({
        config,
        destination: effectiveDestination,
        directDestination: DIRECT,
        combinedDisplayName: t("pages.catalog.routeRuleName", {
          count: selected.size,
        }),
        presets,
        selectedIds: selected,
        sourceDetour: effectiveSourceDetour,
      })
    )
  }

  const confirmAdd = () => {
    if (!config || !addDraft) {
      return
    }
    const nextConfig = applyCatalogAddDraft(config, addDraft)
    const addedCount = addDraft.lists.length
    postConfigMutation.mutate(
      { data: nextConfig },
      {
        onSuccess: () => {
          setSelected(new Set())
          setAddDraft(null)
          toast.success(t("pages.catalog.added", { count: addedCount }))
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

      <div className="flex flex-wrap items-center justify-between gap-3 border-y border-border px-3 py-2">
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
                {outboundDisplayNames.get(tag) ?? tag}
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

      <SectionTabs
        ariaLabel={t("pages.catalog.categoriesAriaLabel")}
        onValueChange={setCategory}
        tabs={categoryTabs}
        value={category}
      />

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

      {/* Каталог прокручивается внутри себя: восемьдесят семь заготовок
          уводили нижнюю панель с выбором маршрута далеко за экран, и
          чтобы нажать «Добавить», приходилось листать обратно. */}
      <div className="max-h-[55vh] divide-y overflow-y-auto border-y">
        {visible.map((preset) => {
          const url = preset.engines?.singbox?.ruleSets?.[0]?.url
          const domains = preset.engines?.dns?.domains?.length ?? 0
          const blocks = preset.engines?.singbox?.action === "reject"
          const already = existingNames.has(sanitizeCatalogListId(preset.id))

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

      <BottomActionBar contentClassName="justify-between">
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
                {outboundDisplayNames.get(tag) ?? tag}
              </option>
            ))}
            <option value={DIRECT}>{t("pages.catalog.directly")}</option>
          </select>
          <Button
            disabled={selected.size === 0 || configMutationPending}
            onClick={openAddDialog}
          >
            {t("pages.catalog.add")}
          </Button>
        </div>
      </BottomActionBar>

      <Dialog
        onOpenChange={(open) => {
          if (!open && !configMutationPending) {
            setAddDraft(null)
          }
        }}
        open={addDraft !== null}
      >
        <DialogContent className="max-h-[90svh] overflow-y-auto sm:max-w-xl">
          <DialogHeader>
            <DialogTitle>{t("pages.catalog.naming.title")}</DialogTitle>
            <DialogDescription>
              {t("pages.catalog.naming.description")}
            </DialogDescription>
          </DialogHeader>
          {addDraft ? (
            <div className="space-y-5">
              <div className="space-y-3">
                {addDraft.lists.map((proposal, index) => (
                  <div className="space-y-1.5" key={proposal.technicalId}>
                    <Label htmlFor={`catalog-list-name-${index}`}>
                      {t("pages.catalog.naming.listName")}
                    </Label>
                    <Input
                      id={`catalog-list-name-${index}`}
                      maxLength={80}
                      onChange={(event) =>
                        setAddDraft((current) =>
                          current
                            ? {
                                ...current,
                                lists: current.lists.map((item, itemIndex) =>
                                  itemIndex === index
                                    ? {
                                        ...item,
                                        displayName: event.target.value,
                                      }
                                    : item
                                ),
                              }
                            : current
                        )
                      }
                      value={proposal.displayName}
                    />
                  </div>
                ))}
              </div>
              {addDraft.routeRule ? (
                <div className="space-y-1.5 border-t border-border pt-4">
                  <Label htmlFor="catalog-route-rule-name">
                    {t("pages.catalog.naming.routeRuleName")}
                  </Label>
                  <Input
                    id="catalog-route-rule-name"
                    maxLength={80}
                    onChange={(event) =>
                      setAddDraft((current) =>
                        current?.routeRule
                          ? {
                              ...current,
                              routeRule: {
                                ...current.routeRule,
                                displayName: event.target.value,
                              },
                            }
                          : current
                      )
                    }
                    value={addDraft.routeRule.displayName}
                  />
                </div>
              ) : null}
              {addDraft.dnsRule ? (
                <div className="space-y-1.5">
                  <Label htmlFor="catalog-dns-rule-name">
                    {t("pages.catalog.naming.dnsRuleName")}
                  </Label>
                  <Input
                    id="catalog-dns-rule-name"
                    maxLength={80}
                    onChange={(event) =>
                      setAddDraft((current) =>
                        current?.dnsRule
                          ? {
                              ...current,
                              dnsRule: {
                                ...current.dnsRule,
                                displayName: event.target.value,
                              },
                            }
                          : current
                      )
                    }
                    value={addDraft.dnsRule.displayName}
                  />
                  <p className="text-xs text-muted-foreground">
                    {t("pages.catalog.naming.dnsRuleHint", {
                      server: addDraft.dnsRule.server,
                    })}
                  </p>
                </div>
              ) : null}
            </div>
          ) : null}
          <DialogFooter>
            <Button
              disabled={configMutationPending}
              onClick={() => setAddDraft(null)}
              variant="outline"
            >
              {t("common.cancel")}
            </Button>
            <Button
              disabled={configMutationPending}
              onClick={confirmAdd}
            >
              {t("pages.catalog.naming.confirm")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { useMemo, useRef, useState } from "react"
import { AlertTriangleIcon, RefreshCw, ShieldCheckIcon } from "lucide-react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"

import type { ApiError } from "@/api/client"
import { useConfigMutationPending } from "@/api/mutations"
import { queryKeys } from "@/api/query-keys"
import { useGetConfig } from "@/api/queries"
import { selectConfig } from "@/api/selectors"
import { BottomActionBar } from "@/components/shared/bottom-action-bar"
import { PageHeader } from "@/components/shared/page-header"
import { SectionTabs, type SectionTab } from "@/components/shared/section-tabs"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
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
import { createOutboundDisplayNameMap } from "@/lib/outbound-display"
import { cn } from "@/lib/utils"
import {
  getCatalogPresetSourceSummary,
  getCatalogSelectionMode,
  isCatalogPresetInstalled,
  isCatalogRoutableOutboundType,
  type CatalogPreset,
} from "@/pages/catalog-model"
import {
  applyCatalogSetup,
  getCatalogSetupInstallState,
  previewCatalogSetup,
  type CatalogSetupPreview,
  type CatalogSetupWarning,
} from "@/pages/catalog-setup-api"
import {
  createCatalogSetupIntent,
  resolveCatalogDestination,
  updateCatalogSetupRuleName,
  updateCatalogSetupSelectionName,
  type CatalogSetupIntent,
} from "@/pages/catalog-setup-intent"

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
  const [setupIntent, setSetupIntent] = useState<CatalogSetupIntent | null>(
    null
  )
  const setupIntentRef = useRef<CatalogSetupIntent | null>(null)
  const [setupPreview, setSetupPreview] = useState<CatalogSetupPreview | null>(
    null
  )
  const [acceptWarnings, setAcceptWarnings] = useState(false)

  // Only outbounds that can actually carry traffic: urltest groups and
  // interfaces/tables qualify. Ignore and blackhole are verdicts, not egress
  // paths. The backend planner repeats this validation authoritatively.
  const outboundTags = (config?.outbounds ?? [])
    .filter((outbound) => isCatalogRoutableOutboundType(outbound.type))
    .map((outbound) => outbound.tag)
  const outboundDisplayNames = createOutboundDisplayNameMap(
    config?.outbounds ?? []
  )

  const effectiveDestination = resolveCatalogDestination(
    destination,
    outboundTags,
    DIRECT
  )
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

  const previewMutation = useMutation({
    mutationFn: previewCatalogSetup,
    onSuccess: (preview, requestedIntent) => {
      if (
        JSON.stringify(requestedIntent) !==
        JSON.stringify(setupIntentRef.current)
      ) {
        return
      }
      setSetupPreview(preview)
      setAcceptWarnings(false)
    },
    onError: (error: ApiError) =>
      toast.error(getApiErrorMessage(error), { richColors: true }),
  })

  const applyMutation = useMutation({
    mutationFn: ({
      intent,
      preview,
      acceptWarnings: accepted,
    }: {
      intent: CatalogSetupIntent
      preview: CatalogSetupPreview
      acceptWarnings: boolean
    }) =>
      applyCatalogSetup({
        intent,
        preview,
        acceptWarnings: accepted,
      }),
    onSuccess: async () => {
      setSelected(new Set())
      setupIntentRef.current = null
      setSetupIntent(null)
      setSetupPreview(null)
      setAcceptWarnings(false)
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: queryKeys.config() }),
        queryClient.invalidateQueries({
          queryKey: queryKeys.healthService(),
        }),
        queryClient.invalidateQueries({
          queryKey: queryKeys.healthRouting(),
        }),
        queryClient.invalidateQueries({
          queryKey: queryKeys.runtimeOutbounds(),
        }),
        queryClient.invalidateQueries({ queryKey: ["catalog"] }),
      ])
      toast.success(t("pages.catalog.setup.applied"))
    },
    onError: (error: ApiError) => {
      // A conflict means the authoritative config or catalogue changed after
      // preview. Never retry with a stale candidate identity.
      if (error.status === 409) {
        setSetupPreview(null)
        setAcceptWarnings(false)
      }
      toast.error(getApiErrorMessage(error), { richColors: true })
    },
  })

  const presets = catalogQuery.data?.presets ?? EMPTY_PRESETS
  const selectedMode = getCatalogSelectionMode(presets, selected)
  const installedPresetIds = new Set(
    presets
      .filter((preset) =>
        isCatalogPresetInstalled(preset, config?.lists)
      )
      .map((preset) => preset.id)
  )

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
    if (selectedMode === "mixed") {
      toast.error(t("pages.catalog.mixedSelection"), { richColors: true })
      return
    }

    const intent = createCatalogSetupIntent({
      destination: effectiveDestination,
      directDestination: DIRECT,
      presets,
      selectedIds: selected,
      selectionMode: selectedMode,
      sourceDetour: effectiveSourceDetour,
      combinedDisplayName: t("pages.catalog.routeRuleName", {
        count: selected.size,
      }),
    })
    if (!intent) {
      toast.error(t("pages.catalog.invalidSelection"), { richColors: true })
      return
    }
    setupIntentRef.current = intent
    setSetupIntent(intent)
    setSetupPreview(null)
    setAcceptWarnings(false)
    previewMutation.mutate(intent)
  }

  const confirmAdd = () => {
    if (!setupIntent || previewMutation.isPending || applyMutation.isPending) {
      return
    }

    if (!setupPreview) {
      previewMutation.mutate(setupIntent)
      return
    }

    applyMutation.mutate({
      intent: setupIntent,
      preview: setupPreview,
      acceptWarnings,
    })
  }

  const updateSetupIntent = (
    update: (current: CatalogSetupIntent) => CatalogSetupIntent
  ) => {
    setSetupIntent((current) => {
      const next = current ? update(current) : current
      setupIntentRef.current = next
      return next
    })
    setSetupPreview(null)
    setAcceptWarnings(false)
  }

  const setupWarningMessage = (warning: CatalogSetupWarning) => {
    switch (warning.code) {
      case "source_detour_not_found":
        return t("pages.catalog.setup.warnings.sourceDetourNotFound")
      case "source_detour_not_routable":
        return t("pages.catalog.setup.warnings.sourceDetourNotRoutable")
      case "source_detour_not_applicable":
        return t("pages.catalog.setup.warnings.sourceDetourNotApplicable")
      case "dns_automatic_unavailable":
        return t("pages.catalog.setup.warnings.dnsAutomaticUnavailable")
      case "dns_ignored_for_block":
        return t("pages.catalog.setup.warnings.dnsIgnoredForBlock")
      case "dns_detour_missing":
        return t("pages.catalog.setup.warnings.dnsDetourMissing")
      case "dns_detour_mismatch":
        return t("pages.catalog.setup.warnings.dnsDetourMismatch")
      default:
        return warning.message
    }
  }

  const setupInstallState = setupPreview
    ? getCatalogSetupInstallState(setupPreview)
    : null

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
          const sourceSummary = getCatalogPresetSourceSummary(preset)
          const blocks = preset.engines?.singbox?.action === "reject"
          const installed = installedPresetIds.has(preset.id)

          return (
            <label
              className="flex cursor-pointer items-center gap-3 px-3 py-2.5 text-sm hover:bg-secondary"
              key={preset.id}
            >
              <input
                checked={selected.has(preset.id)}
                className="size-4 accent-[var(--primary)]"
                onChange={() => toggle(preset.id)}
                type="checkbox"
              />
              <span className="flex min-w-0 flex-1 items-center gap-2">
                <span className="truncate">{preset.name}</span>
                {installed ? (
                  <span className="shrink-0 text-xs font-medium text-success">
                    {t("pages.catalog.installed")}
                  </span>
                ) : null}
              </span>
              <span className="shrink-0 text-xs text-muted-foreground">
                {sourceSummary.urlBacked
                  ? t("pages.catalog.ruleSet")
                  : sourceSummary.domainCount > 0 && sourceSummary.cidrCount > 0
                    ? t("pages.catalog.domainsAndCidrs", {
                        domains: sourceSummary.domainCount,
                        cidrs: sourceSummary.cidrCount,
                      })
                    : sourceSummary.cidrCount > 0
                      ? t("pages.catalog.cidrs", {
                          count: sourceSummary.cidrCount,
                        })
                      : t("pages.catalog.domains", {
                          count: sourceSummary.domainCount,
                        })}
              </span>
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
            </label>
          )
        })}
      </div>

      <BottomActionBar contentClassName="justify-between">
        <span className="text-[13px] text-muted-foreground">
          {t("pages.catalog.selected", { count: selected.size })}
        </span>
        <div className="flex flex-wrap items-center gap-2">
          {selectedMode === "reject" ? (
            <span className="text-[13px] text-destructive">
              {t("pages.catalog.blockSelected")}
            </span>
          ) : (
            <>
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
            </>
          )}
          {selectedMode === "mixed" ? (
            <span className="max-w-80 text-[12px] text-destructive">
              {t("pages.catalog.mixedSelectionShort")}
            </span>
          ) : null}
          <Button
            disabled={
              !config ||
              selected.size === 0 ||
              configMutationPending ||
              previewMutation.isPending ||
              applyMutation.isPending ||
              selectedMode === "mixed"
            }
            onClick={openAddDialog}
          >
            {t("pages.catalog.add")}
          </Button>
        </div>
      </BottomActionBar>

      <Dialog
        onOpenChange={(open) => {
          if (!open && !previewMutation.isPending && !applyMutation.isPending) {
            setupIntentRef.current = null
            setSetupIntent(null)
            setSetupPreview(null)
            setAcceptWarnings(false)
          }
        }}
        open={setupIntent !== null}
      >
        <DialogContent className="max-h-[calc(100dvh-0.75rem)] overflow-y-auto max-sm:top-auto max-sm:bottom-0 max-sm:left-0 max-sm:max-w-none max-sm:translate-x-0 max-sm:translate-y-0 max-sm:rounded-b-none max-sm:border-x-0 max-sm:border-b-0 sm:max-h-[90svh] sm:max-w-xl">
          <DialogHeader>
            <DialogTitle>{t("pages.catalog.naming.title")}</DialogTitle>
            <DialogDescription>
              {t("pages.catalog.naming.description")}
            </DialogDescription>
          </DialogHeader>
          {setupIntent ? (
            <div className="space-y-5">
              <div className="space-y-3">
                {setupIntent.selections.map((selection, index) => (
                  <div className="space-y-1.5" key={selection.preset_id}>
                    <Label htmlFor={`catalog-list-name-${index}`}>
                      {t("pages.catalog.naming.listName")}
                    </Label>
                    <Input
                      disabled={applyMutation.isPending}
                      id={`catalog-list-name-${index}`}
                      maxLength={80}
                      onChange={(event) =>
                        updateSetupIntent((current) =>
                          updateCatalogSetupSelectionName(
                            current,
                            selection.preset_id,
                            event.target.value
                          )
                        )
                      }
                      value={selection.display_name ?? ""}
                    />
                  </div>
                ))}
              </div>
              {setupIntent.mode !== "none" ? (
                <div className="space-y-1.5 border-t border-border pt-4">
                  <Label htmlFor="catalog-route-rule-name">
                    {t("pages.catalog.naming.routeRuleName")}
                  </Label>
                  <Input
                    disabled={applyMutation.isPending}
                    id="catalog-route-rule-name"
                    maxLength={80}
                    onChange={(event) =>
                      updateSetupIntent((current) =>
                        updateCatalogSetupRuleName(
                          current,
                          "route_display_name",
                          event.target.value
                        )
                      )
                    }
                    value={setupIntent.route_display_name ?? ""}
                  />
                </div>
              ) : null}
              {setupIntent.mode === "outbound" &&
              setupIntent.dns_mode !== "none" ? (
                <div className="space-y-1.5">
                  <Label htmlFor="catalog-dns-rule-name">
                    {t("pages.catalog.naming.dnsRuleName")}
                  </Label>
                  <Input
                    disabled={applyMutation.isPending}
                    id="catalog-dns-rule-name"
                    maxLength={80}
                    onChange={(event) =>
                      updateSetupIntent((current) =>
                        updateCatalogSetupRuleName(
                          current,
                          "dns_display_name",
                          event.target.value
                        )
                      )
                    }
                    value={setupIntent.dns_display_name ?? ""}
                  />
                  <p className="text-xs text-muted-foreground">
                    {t("pages.catalog.setup.automaticDnsHint")}
                  </p>
                </div>
              ) : null}

              {previewMutation.isPending ? (
                <div
                  aria-live="polite"
                  className="space-y-2 border-t border-border pt-4"
                >
                  <Skeleton className="h-5 w-48" />
                  <Skeleton className="h-4 w-full" />
                </div>
              ) : null}

              {setupPreview ? (
                <div className="space-y-3 border-t border-border pt-4">
                  <Alert>
                    <ShieldCheckIcon className="size-4" />
                    <AlertTitle>
                      {t("pages.catalog.setup.previewReady")}
                    </AlertTitle>
                    <AlertDescription>
                      {t("pages.catalog.setup.previewSummary", {
                        lists: setupInstallState?.pending.length ?? 0,
                        route: setupPreview.summary.route_rule
                          ? (outboundDisplayNames.get(
                              setupPreview.summary.route_rule.outbound
                            ) ?? setupPreview.summary.route_rule.outbound)
                          : t("pages.catalog.setup.noRoute"),
                        dns: setupPreview.summary.dns_rule?.server
                          ? (config?.dns?.servers?.find(
                              (server) =>
                                server.tag ===
                                setupPreview.summary.dns_rule?.server
                            )?.display_name ??
                            setupPreview.summary.dns_rule.server)
                          : t("pages.catalog.setup.noDnsRule"),
                      })}
                    </AlertDescription>
                  </Alert>

                  {setupInstallState &&
                  setupInstallState.installed.length > 0 ? (
                    <Alert>
                      <ShieldCheckIcon className="size-4" />
                      <AlertTitle>
                        {t("pages.catalog.setup.alreadyInstalledTitle")}
                      </AlertTitle>
                      <AlertDescription>
                        {t("pages.catalog.setup.alreadyInstalled", {
                          lists: setupInstallState.installed
                            .map((list) => list.display_name)
                            .join(", "),
                        })}
                      </AlertDescription>
                    </Alert>
                  ) : null}

                  {setupPreview.warnings.map((warning) => (
                    <Alert
                      key={`${warning.code}:${warning.path}`}
                      variant="warning"
                    >
                      <AlertTriangleIcon className="size-4" />
                      <AlertTitle>
                        {t("pages.catalog.setup.warningTitle")}
                      </AlertTitle>
                      <AlertDescription>
                        {setupWarningMessage(warning)}
                      </AlertDescription>
                    </Alert>
                  ))}

                  {setupPreview.requires_warning_acceptance ? (
                    <label className="flex items-start gap-3 text-sm">
                      <input
                        checked={acceptWarnings}
                        className="mt-0.5 size-4 accent-[var(--primary)]"
                        onChange={(event) =>
                          setAcceptWarnings(event.target.checked)
                        }
                        type="checkbox"
                      />
                      <span>{t("pages.catalog.setup.acceptWarnings")}</span>
                    </label>
                  ) : null}
                </div>
              ) : null}
            </div>
          ) : null}
          <DialogFooter>
            <Button
              disabled={
                configMutationPending ||
                previewMutation.isPending ||
                applyMutation.isPending
              }
              onClick={() => {
                setupIntentRef.current = null
                setSetupIntent(null)
                setSetupPreview(null)
                setAcceptWarnings(false)
              }}
              variant="outline"
            >
              {t("common.cancel")}
            </Button>
            <Button
              disabled={
                configMutationPending ||
                previewMutation.isPending ||
                applyMutation.isPending ||
                Boolean(setupInstallState?.noChanges) ||
                Boolean(
                  setupPreview?.requires_warning_acceptance && !acceptWarnings
                )
              }
              onClick={confirmAdd}
            >
              {applyMutation.isPending
                ? t("pages.catalog.setup.applying")
                : setupInstallState?.noChanges
                  ? t("pages.catalog.setup.alreadyInstalledButton")
                  : setupPreview
                    ? t("pages.catalog.naming.confirm")
                    : t("pages.catalog.setup.preview")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}

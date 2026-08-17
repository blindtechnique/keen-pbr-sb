import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { CheckIcon, Link2Icon, WorkflowIcon } from "lucide-react"
import { useMemo, useState } from "react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"
import { useLocation } from "wouter"

import type { ApiError } from "@/api/client"
import type { Outbound } from "@/api/generated/model/outbound"
import { usePostTransportConfigApplyMutation } from "@/api/mutations"
import { queryKeys } from "@/api/query-keys"
import { useGetConfig, useGetTransportConfig } from "@/api/queries"
import { selectConfig } from "@/api/selectors"
import { PageHeader } from "@/components/shared/page-header"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import { useInterfaceDisplayNames } from "@/hooks/use-interface-display-names"
import { getApiErrorMessage } from "@/lib/api-errors"
import { validateDisplayName } from "@/lib/display-name-validation"
import { getOutboundSelectDisplayName } from "@/lib/outbound-display"
import { cn } from "@/lib/utils"
import {
  applyCatalogSelectionToggle,
  getCatalogSelectionMode,
  isCatalogRoutableOutboundType,
  type CatalogPreset,
} from "@/pages/catalog-model"
import {
  applyCatalogSetup,
  getCatalogSetupInstallState,
  previewCatalogSetup,
  type CatalogSetupPreview,
} from "@/pages/catalog-setup-api"
import { getCatalogSetupWarningMessage } from "@/pages/catalog-setup-warning"
import {
  createCatalogSetupIntent,
  type CatalogSetupIntent,
} from "@/pages/catalog-setup-intent"
import {
  createSetupWizardTransport,
  previewSetupWizardCatalog,
  SetupWizardVisibleDraftError,
} from "@/pages/setup-wizard-flow"

type WizardStep = 1 | 2 | 3

const DIRECT = "__direct__"

export default function SetupWizardPage() {
  const { t } = useTranslation()
  const [, navigate] = useLocation()
  const queryClient = useQueryClient()
  const configQuery = useGetConfig()
  const transportConfigQuery = useGetTransportConfig()
  const loadedConfig = selectConfig(configQuery.data)
  const { labelFor: interfaceLabelFor } = useInterfaceDisplayNames()

  const [step, setStep] = useState<WizardStep>(1)
  const [link, setLink] = useState("")
  const [tunnelName, setTunnelName] = useState("")
  const [existingOutboundTag, setExistingOutboundTag] = useState("")
  const [outboundTag, setOutboundTag] = useState("")
  const [outboundName, setOutboundName] = useState("")
  const [selectedPresets, setSelectedPresets] = useState<ReadonlySet<string>>(
    new Set()
  )
  const [routedCount, setRoutedCount] = useState(0)
  const [previewState, setPreviewState] = useState<{
    readonly intent: CatalogSetupIntent
    readonly preview: CatalogSetupPreview
  } | null>(null)

  const existingOutbounds = loadedConfig?.outbounds ?? []
  const routableOutbounds = existingOutbounds.filter(
    (outbound): outbound is Outbound & { tag: string } =>
      Boolean(outbound.tag) && isCatalogRoutableOutboundType(outbound.type)
  )
  const configured =
    transportConfigQuery.data?.status === 200
      ? transportConfigQuery.data.data
      : []
  const setupInventoryReady =
    configQuery.data?.status === 200 &&
    transportConfigQuery.data?.status === 200
  const setupInventoryLoading =
    !setupInventoryReady &&
    (configQuery.isLoading || transportConfigQuery.isLoading)
  const setupInventoryUnavailable =
    !setupInventoryReady && !setupInventoryLoading

  const catalogQuery = useQuery<{ presets?: CatalogPreset[] }>({
    queryKey: ["catalog"],
    queryFn: async () => {
      const response = await fetch("/api/catalog")
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      return response.json()
    },
    enabled: step === 2,
  })
  const routePresets = useMemo(
    () =>
      (catalogQuery.data?.presets ?? []).filter(
        (preset) =>
          !preset.hidden && preset.engines?.singbox?.action !== "reject"
      ),
    [catalogQuery.data?.presets]
  )

  const nameError = validateDisplayName(tunnelName)
  const createTunnelMutation = usePostTransportConfigApplyMutation()

  const createTunnel = async () => {
    try {
      if (!setupInventoryReady || !loadedConfig) {
        throw new Error(t("pages.setupWizard.connection.inventoryUnavailable"))
      }
      const result = await createSetupWizardTransport(
        {
          displayName: tunnelName,
          existingInterfaces: [
            ...configured.map((item) => item.interface),
            ...existingOutbounds.flatMap((outbound) =>
              outbound.type === "interface" && outbound.interface
                ? [outbound.interface]
                : []
            ),
          ],
          existingTags: [
            ...configured.map((item) => item.tag),
            ...existingOutbounds.map((outbound) => outbound.tag),
          ],
          link,
        },
        {
          applyTransport: (request) =>
            createTunnelMutation.mutateAsync({ data: request }),
        }
      )
      setOutboundTag(result.outboundTag)
      setOutboundName(result.displayName)
      setStep(2)
    } catch (error) {
      toast.error(getApiErrorMessage(error as ApiError), { richColors: true })
    }
  }

  const setupMutation = useMutation({
    mutationFn: async ({ acceptWarnings }: { acceptWarnings: boolean }) => {
      const intent =
        previewState?.intent ??
        createCatalogSetupIntent({
          presets: routePresets,
          selectedIds: selectedPresets,
          selectionMode: getCatalogSelectionMode(routePresets, selectedPresets),
          destination: outboundTag,
          directDestination: DIRECT,
          sourceDetour: "",
          combinedDisplayName: "",
        })
      if (!intent) {
        throw new Error(t("pages.setupWizard.services.selectionInvalid"))
      }

      const nextPreview =
        previewState?.preview ??
        (await previewSetupWizardCatalog(intent, {
          reloadActiveConfig: async () => {
            const result = await configQuery.refetch()
            if (result.data?.status !== 200) {
              throw new Error(t("pages.setupWizard.services.configUnavailable"))
            }
            return { isDraft: result.data.data.is_draft }
          },
          previewCatalog: previewCatalogSetup,
        }))
      if (nextPreview.requires_warning_acceptance && !acceptWarnings) {
        return { pendingPreview: { intent, preview: nextPreview } }
      }

      if (getCatalogSetupInstallState(nextPreview).noChanges) {
        return { applied: selectedPresets.size }
      }

      await applyCatalogSetup({
        intent,
        preview: nextPreview,
        acceptWarnings,
      })
      return { applied: selectedPresets.size }
    },
    onSuccess: async (result) => {
      if ("pendingPreview" in result && result.pendingPreview) {
        setPreviewState(result.pendingPreview)
        return
      }

      setPreviewState(null)
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: queryKeys.config() }),
        queryClient.invalidateQueries({ queryKey: queryKeys.healthService() }),
        queryClient.invalidateQueries({ queryKey: queryKeys.healthRouting() }),
        queryClient.invalidateQueries({
          queryKey: queryKeys.runtimeOutbounds(),
        }),
        queryClient.invalidateQueries({ queryKey: ["catalog"] }),
      ])
      setRoutedCount(selectedPresets.size)
      setStep(3)
    },
    onError: (error: ApiError) => {
      if (error.status === 409) {
        setPreviewState(null)
      }
      toast.error(
        error instanceof SetupWizardVisibleDraftError
          ? t("pages.setupWizard.services.draftBlocked")
          : getApiErrorMessage(error),
        { richColors: true }
      )
    },
  })

  const steps: readonly { id: WizardStep; label: string }[] = [
    { id: 1, label: t("pages.setupWizard.steps.connection") },
    { id: 2, label: t("pages.setupWizard.steps.services") },
    { id: 3, label: t("pages.setupWizard.steps.done") },
  ]

  return (
    <div className="space-y-3">
      <PageHeader
        description={t("pages.setupWizard.description")}
        title={t("pages.setupWizard.title")}
      />

      <ol className="flex flex-wrap items-center gap-2 text-sm">
        {steps.map((item, index) => (
          <li className="flex items-center gap-2" key={item.id}>
            {index > 0 ? (
              <span aria-hidden className="text-muted-foreground">
                —
              </span>
            ) : null}
            <span
              className={cn(
                "flex items-center gap-1.5",
                step === item.id
                  ? "font-medium text-foreground"
                  : "text-muted-foreground"
              )}
            >
              <span
                className={cn(
                  "flex size-5 items-center justify-center rounded-full border text-xs",
                  step > item.id
                    ? "border-primary bg-primary text-primary-foreground"
                    : step === item.id
                      ? "border-primary text-primary"
                      : "border-border"
                )}
              >
                {step > item.id ? <CheckIcon className="size-3" /> : item.id}
              </span>
              {item.label}
            </span>
          </li>
        ))}
      </ol>

      {step === 1 ? (
        <section className="max-w-[640px] space-y-4">
          <div className="space-y-1">
            <h2 className="text-base font-semibold">
              {t("pages.setupWizard.connection.title")}
            </h2>
            <p className="text-sm text-muted-foreground">
              {t("pages.setupWizard.connection.description")}
            </p>
          </div>

          {setupInventoryLoading ? (
            <p className="text-sm text-muted-foreground">
              {t("pages.setupWizard.connection.inventoryLoading")}
            </p>
          ) : null}

          {setupInventoryUnavailable ? (
            <Alert variant="destructive">
              <AlertTitle>
                {t("pages.setupWizard.connection.inventoryErrorTitle")}
              </AlertTitle>
              <AlertDescription className="space-y-2">
                <p>{t("pages.setupWizard.connection.inventoryUnavailable")}</p>
                <Button
                  disabled={
                    configQuery.isFetching || transportConfigQuery.isFetching
                  }
                  onClick={() =>
                    void Promise.all([
                      configQuery.refetch(),
                      transportConfigQuery.refetch(),
                    ])
                  }
                  size="sm"
                  variant="outline"
                >
                  {t("common.retry")}
                </Button>
              </AlertDescription>
            </Alert>
          ) : null}

          <div className="grid gap-1.5">
            <Label htmlFor="setup-link">
              {t("pages.setupWizard.connection.linkLabel")}
            </Label>
            <Textarea
              className="min-h-24 font-mono text-xs"
              disabled={!setupInventoryReady || createTunnelMutation.isPending}
              id="setup-link"
              onChange={(event) => setLink(event.target.value)}
              placeholder="vless://…, trojan://…, hy2://…"
              value={link}
            />
            <p className="text-xs text-muted-foreground">
              {t("pages.setupWizard.connection.linkHint")}
            </p>
          </div>

          <div className="grid max-w-[480px] gap-1.5">
            <Label htmlFor="setup-name">
              {t("pages.setupWizard.connection.nameLabel")}
            </Label>
            <Input
              id="setup-name"
              disabled={!setupInventoryReady || createTunnelMutation.isPending}
              onChange={(event) => setTunnelName(event.target.value)}
              placeholder={t("pages.setupWizard.connection.namePlaceholder")}
              value={tunnelName}
            />
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Button
              disabled={
                !link.trim() ||
                Boolean(nameError) ||
                !tunnelName.trim() ||
                !setupInventoryReady ||
                createTunnelMutation.isPending
              }
              onClick={() => void createTunnel()}
            >
              <Link2Icon />
              {createTunnelMutation.isPending
                ? t("pages.setupWizard.connection.creating")
                : t("pages.setupWizard.connection.create")}
            </Button>
          </div>

          {routableOutbounds.length > 0 ? (
            <div className="space-y-2 border-t pt-4">
              <p className="text-sm text-muted-foreground">
                {t("pages.setupWizard.connection.existingHint")}
              </p>
              <div className="flex flex-wrap items-center gap-2">
                <select
                  aria-label={t("pages.setupWizard.connection.existingLabel")}
                  className="h-8 max-w-[320px] min-w-0 rounded-lg border border-input bg-transparent px-2 text-sm"
                  disabled={
                    !setupInventoryReady || createTunnelMutation.isPending
                  }
                  onChange={(event) =>
                    setExistingOutboundTag(event.target.value)
                  }
                  value={existingOutboundTag}
                >
                  <option value="">
                    {t("pages.setupWizard.connection.existingPlaceholder")}
                  </option>
                  {routableOutbounds.map((outbound) => (
                    <option key={outbound.tag} value={outbound.tag}>
                      {getOutboundSelectDisplayName(
                        outbound,
                        interfaceLabelFor
                      )}
                    </option>
                  ))}
                </select>
                <Button
                  disabled={
                    !setupInventoryReady ||
                    !existingOutboundTag ||
                    createTunnelMutation.isPending
                  }
                  onClick={() => {
                    const outbound = routableOutbounds.find(
                      (item) => item.tag === existingOutboundTag
                    )
                    if (!outbound) return
                    setOutboundTag(outbound.tag)
                    setOutboundName(
                      getOutboundSelectDisplayName(outbound, interfaceLabelFor)
                    )
                    setStep(2)
                  }}
                  variant="outline"
                >
                  {t("pages.setupWizard.connection.useExisting")}
                </Button>
              </div>
            </div>
          ) : null}
        </section>
      ) : null}

      {step === 2 ? (
        <section className="space-y-4">
          <div className="max-w-[640px] space-y-1">
            <h2 className="text-base font-semibold">
              {t("pages.setupWizard.services.title")}
            </h2>
            <p className="text-sm text-muted-foreground">
              {t("pages.setupWizard.services.description", {
                name: outboundName,
              })}
            </p>
          </div>

          {catalogQuery.isLoading ? (
            <p className="text-sm text-muted-foreground">
              {t("pages.setupWizard.services.loading")}
            </p>
          ) : catalogQuery.isError ? (
            <Alert variant="destructive">
              <AlertTitle>
                {t("pages.setupWizard.services.catalogErrorTitle")}
              </AlertTitle>
              <AlertDescription className="space-y-2">
                <p>{t("pages.setupWizard.services.catalogUnavailable")}</p>
                <Button
                  disabled={catalogQuery.isFetching}
                  onClick={() => void catalogQuery.refetch()}
                  size="sm"
                  variant="outline"
                >
                  {t("common.retry")}
                </Button>
              </AlertDescription>
            </Alert>
          ) : routePresets.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              {t("pages.setupWizard.services.empty")}
            </p>
          ) : (
            <ul className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
              {routePresets.map((preset) => {
                const checked = selectedPresets.has(preset.id)
                return (
                  <li key={preset.id}>
                    <label
                      className={cn(
                        "flex cursor-pointer items-start gap-2 rounded-xl border p-3 transition-colors",
                        checked
                          ? "border-primary bg-primary/5"
                          : "hover:border-ring",
                        setupMutation.isPending && "cursor-wait opacity-70"
                      )}
                    >
                      <Checkbox
                        checked={checked}
                        disabled={setupMutation.isPending}
                        onCheckedChange={(next) => {
                          setPreviewState(null)
                          if (next === true || next === false) {
                            setSelectedPresets((current) =>
                              applyCatalogSelectionToggle(
                                routePresets,
                                current,
                                preset.id
                              )
                            )
                          }
                        }}
                      />
                      <span className="min-w-0">
                        <span className="block truncate text-sm font-medium">
                          {preset.name}
                        </span>
                        {preset.category ? (
                          <span className="block text-xs text-muted-foreground">
                            {preset.category}
                          </span>
                        ) : null}
                      </span>
                    </label>
                  </li>
                )
              })}
            </ul>
          )}

          {previewState?.preview.requires_warning_acceptance ? (
            <Alert variant="warning">
              <AlertTitle>
                {t("pages.setupWizard.services.warningsTitle")}
              </AlertTitle>
              <AlertDescription className="space-y-2">
                {previewState.preview.warnings.length > 0 ? (
                  <ul className="list-disc pl-4">
                    {previewState.preview.warnings.map((warning, index) => (
                      <li key={index}>
                        {getCatalogSetupWarningMessage(warning, t)}
                      </li>
                    ))}
                  </ul>
                ) : null}
                <Button
                  disabled={setupMutation.isPending}
                  onClick={() => setupMutation.mutate({ acceptWarnings: true })}
                  size="sm"
                  variant="outline"
                >
                  {t("pages.setupWizard.services.acceptWarnings")}
                </Button>
              </AlertDescription>
            </Alert>
          ) : null}

          <div className="flex flex-wrap items-center gap-2">
            <Button
              disabled={selectedPresets.size === 0 || setupMutation.isPending}
              onClick={() => setupMutation.mutate({ acceptWarnings: false })}
            >
              <WorkflowIcon />
              {setupMutation.isPending
                ? t("pages.setupWizard.services.applying")
                : t("pages.setupWizard.services.route", {
                    count: selectedPresets.size,
                  })}
            </Button>
            <Button
              disabled={setupMutation.isPending}
              onClick={() => {
                setRoutedCount(0)
                setStep(3)
              }}
              variant="outline"
            >
              {t("pages.setupWizard.services.skip")}
            </Button>
          </div>
        </section>
      ) : null}

      {step === 3 ? (
        <section className="max-w-[640px] space-y-4">
          <div className="space-y-1">
            <h2 className="text-base font-semibold">
              {t("pages.setupWizard.done.title")}
            </h2>
            <p className="text-sm text-muted-foreground">
              {routedCount > 0
                ? t("pages.setupWizard.done.summary", {
                    name: outboundName,
                    count: routedCount,
                  })
                : t("pages.setupWizard.done.summaryNoLists", {
                    name: outboundName,
                  })}
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Button onClick={() => navigate("/")}>
              {t("pages.setupWizard.done.openDashboard")}
            </Button>
            <Button onClick={() => navigate("/transports")} variant="outline">
              {t("pages.setupWizard.done.openTunnels")}
            </Button>
            <Button onClick={() => navigate("/rules")} variant="outline">
              {t("pages.setupWizard.done.openRules")}
            </Button>
          </div>
        </section>
      ) : null}
    </div>
  )
}

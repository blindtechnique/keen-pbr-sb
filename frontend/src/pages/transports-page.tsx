import {
  ChevronDownIcon,
  PencilIcon,
  PlusIcon,
  DownloadIcon,
  EyeIcon,
  EyeOffIcon,
  RefreshCwIcon,
  ShieldCheckIcon,
  TrashIcon,
  UploadIcon,
  WorkflowIcon,
} from "lucide-react"
import { useEffect, useMemo, useRef, useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"
import { useLocation } from "wouter"

import type { ApiError } from "@/api/client"
import {
  getTransportConfigExport,
  postTransportConfig,
} from "@/api/generated/keen-api"
import {
  TransportActionRequestAction,
  TransportConfigOperationOperation,
  type TransportSpec,
  type TransportStatus,
} from "@/api/generated/model"
import {
  createLinkedTransportApplyRequest,
  usePostTransportConfigApplyMutation,
  usePostTransportActionMutation,
  usePostTransportConfigMutation,
  usePostConfigMutation,
} from "@/api/mutations"
import {
  useGetConfig,
  useGetNdmsInterfaceInventory,
  useGetRuntimeInterfaces,
  useGetRuntimeOutbounds,
  useGetTransportConfig,
  useGetTransports,
} from "@/api/queries"
import { selectConfig } from "@/api/selectors"
import { DeleteImpactDialog } from "@/components/shared/delete-impact-dialog"
import { KeeneticStatus } from "@/components/shared/keenetic-status"
import { PageActionBar } from "@/components/shared/page-action-bar"
import { PageHeader } from "@/components/shared/page-header"
import { SectionTabs, type SectionTab } from "@/components/shared/section-tabs"
import { NativeInterfaceCard } from "@/components/transports/native-interface-card"
import { InterfaceTraffic } from "@/components/transports/interface-traffic"
import { TransportLatencyPill } from "@/components/transports/transport-latency-pill"
import {
  collectProbeByInterface,
  collectRuntimeLatencyByInterface,
} from "@/components/transports/transport-latency-model"
import { TransportProtocolIcon } from "@/components/transports/protocol-icon"
import { formatTransportPath } from "@/components/transports/transport-path"
import { TransportConfigDialog } from "@/components/transports/transport-config-dialog"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Switch } from "@/components/ui/switch"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardAction,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { getApiErrorMessage } from "@/lib/api-errors"
import {
  useServerLocations,
  type ServerLocation,
} from "@/hooks/use-server-locations"
import { useRunSystemProbes } from "@/hooks/use-run-system-probes"
import { cn } from "@/lib/utils"
import { downloadJson, formatDownloadTimestamp } from "@/lib/download"
import { queryKeys } from "@/api/query-keys"
import { countryFlag } from "@/data/countries"
import { useSectionTab } from "@/hooks/use-section-tab"
import {
  dedupeLegacyNativeTransports,
  mapNativeInterfaces,
} from "@/lib/native-interfaces"
import {
  buildNativeTransportCandidates,
  getHiddenNativeInterfaceIds,
  updateHiddenNativeInterfacePreference,
} from "@/lib/hidden-native-interfaces"

type ProbeEntry = {
  success: boolean
  latency_ms: number
  age_seconds: number
  error?: string
  interface?: string
}

type ProbesResponse = {
  interval_seconds: number
  probes: Record<string, ProbeEntry>
}

type TransportProviderGroup = {
  key: string
  label: string
  items: TransportStatus[]
}

function transportProvider(item: TransportStatus, otherLabel: string) {
  const type = item.type.trim().toLowerCase()
  const protocol = item.protocol?.trim().toLowerCase() ?? ""

  // A native tracker is owned outside transport-manager even when its
  // protocol happens to be WireGuard. Ownership takes precedence over the
  // protocol tab so lifecycle controls can never leak onto Keenetic objects.
  if (type === "native" || type.includes("keenetic")) {
    return { key: "keenetic", label: "KeeneticOS" }
  }
  if (type.includes("sing")) {
    return { key: "sing-box", label: "sing-box" }
  }
  if (
    type.includes("amnezia") ||
    protocol.includes("amnezia") ||
    protocol === "awg"
  ) {
    return { key: "amneziawg", label: "AmneziaWG" }
  }
  if (type.includes("freeturn") || protocol.includes("freeturn")) {
    return { key: "freeturn", label: "FreeTurn" }
  }
  if (type.includes("wdtt") || protocol.includes("wdtt")) {
    return { key: "wdtt", label: "WDTT" }
  }
  if (
    type.includes("wireguard") ||
    protocol.includes("wireguard") ||
    protocol === "wg"
  ) {
    return { key: "wireguard", label: "WireGuard" }
  }
  const label = item.type.trim() || otherLabel
  const normalizedKey = label.toLowerCase().replace(/[^a-z0-9]+/g, "-")
  return {
    key: normalizedKey || "other",
    label,
  }
}

function groupTransports(
  items: TransportStatus[],
  otherLabel: string
): TransportProviderGroup[] {
  const groups = new Map<string, TransportProviderGroup>()

  for (const item of items) {
    const provider = transportProvider(item, otherLabel)
    const group = groups.get(provider.key)
    if (group) {
      group.items.push(item)
    } else {
      groups.set(provider.key, { ...provider, items: [item] })
    }
  }

  return [...groups.values()]
}

export function TransportsPage() {
  const queryClient = useQueryClient()
  const { t, i18n } = useTranslation()
  const [, navigate] = useLocation()
  const [dialogOpen, setDialogOpen] = useState(false)
  const [editing, setEditing] = useState<TransportSpec | undefined>()
  const [deleting, setDeleting] = useState<TransportSpec | undefined>()
  const [transportExportPending, setTransportExportPending] = useState(false)
  const [expandedTransportIds, setExpandedTransportIds] = useState(
    () => new Set<string>()
  )
  const [requestedProbe, setRequestedProbe] = useState<{
    interfaceName: string
    baselineRuntimeUpdatedAt: number
  } | null>(null)
  const [showHiddenNative, setShowHiddenNative] = useState(false)
  const transportImportRef = useRef<HTMLInputElement>(null)
  const query = useGetTransports({
    query: {
      refetchInterval: 3_000,
      refetchIntervalInBackground: false,
    },
  })
  const items: TransportStatus[] = useMemo(
    () => (query.data?.status === 200 ? query.data.data : []),
    [query.data]
  )
  const ndmsInventoryQuery = useGetNdmsInterfaceInventory()
  const runtimeInterfacesQuery = useGetRuntimeInterfaces()
  const keenConfigQuery = useGetConfig()
  const keenConfig = selectConfig(keenConfigQuery.data)
  const hiddenNativeIds = getHiddenNativeInterfaceIds(keenConfig)
  const runtimeInterfaceByName = useMemo(
    () =>
      new Map(
        (runtimeInterfacesQuery.data?.status === 200
          ? runtimeInterfacesQuery.data.data.interfaces
          : []
        ).map((runtimeInterface) => [runtimeInterface.name, runtimeInterface])
      ),
    [runtimeInterfacesQuery.data]
  )
  const nativeInterfaces = useMemo(
    () =>
      mapNativeInterfaces(
        ndmsInventoryQuery.data?.status === 200 &&
          ndmsInventoryQuery.data.data.available
          ? ndmsInventoryQuery.data.data.interfaces
          : [],
        runtimeInterfacesQuery.data?.status === 200
          ? runtimeInterfacesQuery.data.data.interfaces
          : []
      ),
    [ndmsInventoryQuery.data, runtimeInterfacesQuery.data]
  )
  const managedItems = useMemo(
    () => dedupeLegacyNativeTransports(items, nativeInterfaces),
    [items, nativeInterfaces]
  )
  const hiddenNativeCount = nativeInterfaces.filter((nativeInterface) =>
    hiddenNativeIds.has(nativeInterface.id)
  ).length
  const nativeTransportCandidates = buildNativeTransportCandidates(
    nativeInterfaces,
    keenConfig
  )
  const displayedNativeInterfaces = nativeInterfaces.filter(
    (nativeInterface) =>
      showHiddenNative || !hiddenNativeIds.has(nativeInterface.id)
  )
  const providerGroups = useMemo(
    () => groupTransports(managedItems, t("transports.tabs.other")),
    [managedItems, t]
  )
  const transportTabs = useMemo<SectionTab<string>[]>(() => {
    const providerTabs = providerGroups.map((group) => ({
      value: group.key,
      label: group.label,
      count: group.items.length,
    }))
    if (displayedNativeInterfaces.length > 0) {
      const keeneticTab = providerTabs.find((tab) => tab.value === "keenetic")
      if (keeneticTab) {
        keeneticTab.count += displayedNativeInterfaces.length
      } else {
        providerTabs.push({
          value: "keenetic",
          label: "KeeneticOS",
          count: displayedNativeInterfaces.length,
        })
      }
    }

    return providerTabs.length > 1
      ? [
          {
            value: "all",
            label: t("transports.tabs.all"),
            count: managedItems.length + displayedNativeInterfaces.length,
          },
          ...providerTabs,
        ]
      : providerTabs
  }, [displayedNativeInterfaces.length, managedItems.length, providerGroups, t])
  const transportTabValues =
    transportTabs.length > 0 ? transportTabs.map((tab) => tab.value) : ["all"]
  const [activeTransportTab, setActiveTransportTab] = useSectionTab(
    transportTabValues,
    transportTabValues[0] ?? "all"
  )
  const visibleItems =
    activeTransportTab === "all"
      ? managedItems
      : (providerGroups.find((group) => group.key === activeTransportTab)
          ?.items ?? [])
  const visibleNativeInterfaces =
    activeTransportTab === "all" || activeTransportTab === "keenetic"
      ? displayedNativeInterfaces
      : []
  const setTransportExpanded = (id: string, expanded: boolean) => {
    setExpandedTransportIds((current) => {
      const next = new Set(current)
      if (expanded) {
        next.add(id)
      } else {
        next.delete(id)
      }
      return next
    })
  }
  const setNativeHidden = (id: string, hidden: boolean) => {
    if (!keenConfig) return
    preferenceMutation.mutate({
      data: updateHiddenNativeInterfacePreference(keenConfig, id, hidden),
    })
  }
  const configQuery = useGetTransportConfig()
  const configured: TransportSpec[] =
    configQuery.data?.status === 200 ? configQuery.data.data : []
  const configuredByTag = new Map(configured.map((spec) => [spec.tag, spec]))
  const autoGeoHosts = items
    .filter((item) => configuredByTag.get(item.tag)?.geo_mode === "auto")
    .map((item) => item.server ?? "")
  const { locationOf } = useServerLocations(autoGeoHosts, {
    // `geo_mode=auto` is persisted only after the user explicitly accepts
    // the external lookup warning in the transport form.
    allowExternalLookup: autoGeoHosts.length > 0,
  })

  // libcronet.so — сетевой стек Chromium, без которого sing-box не умеет
  // naive. Он весит десятки мегабайт, поэтому не ставится вместе с пакетом:
  // спрашиваем только когда naive-транспорт действительно появился.
  const naiveComponentQuery = useQuery<{ installed: boolean }>({
    queryKey: ["naive-component"],
    queryFn: async () => {
      const response = await fetch("/api/system/naive-component")
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      return response.json()
    },
    staleTime: 60_000,
    retry: false,
    enabled: items.some((item) => item.protocol === "naive"),
  })
  const naiveInstallMutation = useMutation({
    mutationFn: async () => {
      const response = await fetch("/api/system/naive-component", {
        method: "POST",
      })
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      return (await response.json()) as { installed: boolean; log?: string }
    },
    onSuccess: async (body) => {
      await queryClient.invalidateQueries({ queryKey: ["naive-component"] })
      if (body.installed) {
        toast.success(t("transports.naiveComponent.installed"))
      } else {
        toast.error(body.log || t("transports.naiveComponent.failed"), {
          richColors: true,
        })
      }
    },
    onError: () => toast.error(t("transports.naiveComponent.failed")),
  })
  const needsNaiveComponent =
    items.some((item) => item.protocol === "naive") &&
    naiveComponentQuery.data?.installed === false
  const error = getApiErrorMessage(query.error as ApiError | null)
  const runtimeOutboundsQuery = useGetRuntimeOutbounds()
  const probesQuery = useQuery<ProbesResponse>({
    queryKey: ["system-probes"],
    queryFn: async () => {
      const response = await fetch("/api/system/probes")
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      return response.json()
    },
    refetchInterval: 10_000,
    refetchIntervalInBackground: false,
  })
  const refetchProbes = probesQuery.refetch

  const runProbeMutation = useRunSystemProbes()

  useEffect(() => {
    if (
      !requestedProbe ||
      runtimeOutboundsQuery.dataUpdatedAt <=
        requestedProbe.baselineRuntimeUpdatedAt
    ) {
      return
    }

    let active = true
    const completedRequest = requestedProbe
    void refetchProbes().finally(() => {
      if (!active) return
      setRequestedProbe((current) =>
        current === completedRequest ? null : current
      )
    })
    return () => {
      active = false
    }
  }, [refetchProbes, requestedProbe, runtimeOutboundsQuery.dataUpdatedAt])

  useEffect(() => {
    if (!requestedProbe) return
    const expiredRequest = requestedProbe
    const timeout = window.setTimeout(() => {
      setRequestedProbe((current) =>
        current === expiredRequest ? null : current
      )
    }, 30_000)
    return () => window.clearTimeout(timeout)
  }, [requestedProbe])

  const refreshLatency = (interfaceName: string) => {
    setRequestedProbe({
      interfaceName,
      baselineRuntimeUpdatedAt: runtimeOutboundsQuery.dataUpdatedAt,
    })
    runProbeMutation.mutate(undefined, {
      onError: () => setRequestedProbe(null),
    })
  }
  const latencyRefreshPending = (interfaceName: string) =>
    requestedProbe?.interfaceName === interfaceName

  const interfaceOutboundByInterface = new Map(
    (keenConfig?.outbounds ?? [])
      .filter(
        (outbound) =>
          outbound.type === "interface" &&
          typeof outbound.interface === "string" &&
          outbound.interface.length > 0
      )
      .map((outbound) => [outbound.interface!, outbound])
  )
  const preferredOutboundTagByInterface = new Map(
    [...interfaceOutboundByInterface].map(([interfaceName, outbound]) => [
      interfaceName,
      outbound.tag,
    ])
  )
  const probeByInterface = collectProbeByInterface(
    probesQuery.data?.probes ?? {},
    preferredOutboundTagByInterface
  )
  const transportLatencyByInterface = collectRuntimeLatencyByInterface(
    runtimeOutboundsQuery.data?.status === 200
      ? runtimeOutboundsQuery.data.data.outbounds
      : [],
    preferredOutboundTagByInterface
  )
  // DNS detour is a property of the DNS server, not of the transport, so the
  // card only points at it instead of duplicating the setting.
  const dnsServersByInterface = new Map<string, string[]>()
  const outboundInterfaces = (tag: string, depth = 0): string[] => {
    if (depth > 4) return []
    const outbound = (keenConfig?.outbounds ?? []).find(
      (candidate) => candidate.tag === tag
    )
    if (!outbound) return []
    if (outbound.interface) return [outbound.interface]
    // A detour may point at a failover group, so expand it to its members.
    return (outbound.outbound_groups ?? []).flatMap((group) =>
      (group.outbounds ?? []).flatMap((child) =>
        outboundInterfaces(child, depth + 1)
      )
    )
  }
  for (const server of keenConfig?.dns?.servers ?? []) {
    if (!server.detour || !server.tag) continue
    for (const interfaceName of outboundInterfaces(server.detour)) {
      const current = dnsServersByInterface.get(interfaceName) ?? []
      if (!current.includes(server.tag)) current.push(server.tag)
      dnsServersByInterface.set(interfaceName, current)
    }
  }
  const environmentQuery = useQuery({
    queryKey: ["transport-environment"],
    queryFn: async () => {
      const response = await fetch("/api/transports/environment")
      if (!response.ok) throw new Error("transport environment unavailable")
      return (await response.json()) as {
        sing_box_installed: boolean
        sing_box_binary: string
        tested_version: string
        transport_api_version?: number
      }
    },
  })
  const actionMutation = usePostTransportActionMutation({
    mutation: {
      onSuccess: (_data, variables) => {
        toast.success(
          variables.data.action === TransportActionRequestAction.up
            ? t("transports.started")
            : variables.data.action === TransportActionRequestAction.restart
              ? t("transports.restarted")
              : t("transports.stopped")
        )
      },
      onError: (mutationError) => {
        toast.error(getApiErrorMessage(mutationError as ApiError), {
          richColors: true,
        })
      },
    },
  })
  const configMutation = usePostTransportConfigMutation({
    mutation: {
      onSuccess: (_data, variables) => {
        setDialogOpen(false)
        setEditing(undefined)
        setDeleting(undefined)
        toast.success(
          t(`transports.configMessages.${variables.data.operation}`)
        )
      },
      onError: (mutationError) => {
        toast.error(getApiErrorMessage(mutationError as ApiError), {
          richColors: true,
        })
      },
    },
  })
  const configApplyMutation = usePostTransportConfigApplyMutation()
  const transferMutation = useMutation({
    mutationFn: async (file: File) => {
      const parsed = JSON.parse(await file.text()) as {
        format?: string
        version?: number
        kind?: string
        transports?: TransportSpec[]
      }
      if (
        parsed.format !== "keen-pbr-sb" ||
        parsed.version !== 1 ||
        parsed.kind !== "transports" ||
        !Array.isArray(parsed.transports)
      ) {
        throw new Error(t("configTransfer.invalidFormat"))
      }
      const imported = parsed.transports
      if (
        imported.some(
          (item) =>
            !item ||
            typeof item.tag !== "string" ||
            typeof item.type !== "string" ||
            typeof item.interface !== "string"
        ) ||
        new Set(imported.map((item) => item.tag)).size !== imported.length
      ) {
        throw new Error(t("configTransfer.invalidFormat"))
      }

      const existingTags = new Set(configured.map((item) => item.tag))
      const conflicts = imported.filter((item) => existingTags.has(item.tag))
      const replaceConflicts =
        conflicts.length === 0 ||
        window.confirm(
          t("configTransfer.replaceTransportConflicts", {
            tags: conflicts.map((item) => item.tag).join(", "),
          })
        )

      for (const transport of imported) {
        const exists = existingTags.has(transport.tag)
        if (exists && !replaceConflicts) continue
        const response = await postTransportConfig({
          operation: exists
            ? TransportConfigOperationOperation.update
            : TransportConfigOperationOperation.create,
          tag: exists ? transport.tag : undefined,
          transport,
        })
        if (response.status !== 200) {
          throw new Error(
            "error" in response.data
              ? response.data.error
              : `HTTP ${response.status}`
          )
        }
      }
    },
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: queryKeys.transports() }),
        queryClient.invalidateQueries({
          queryKey: queryKeys.transportConfig(),
        }),
      ])
      toast.success(t("configTransfer.imported"))
    },
    onError: (transferError) =>
      toast.error(
        transferError instanceof Error
          ? transferError.message
          : t("configTransfer.invalidFormat"),
        { richColors: true }
      ),
    onSettled: () => {
      if (transportImportRef.current) transportImportRef.current.value = ""
    },
  })

  const exportTransports = async () => {
    if (!window.confirm(t("configTransfer.transportSecretsWarning"))) return
    setTransportExportPending(true)
    try {
      const response = await getTransportConfigExport({
        cache: "no-store",
      })
      if (response.status !== 200) throw new Error(response.data.error)
      downloadJson(`keen-pbr-sb-transports-${formatDownloadTimestamp()}.json`, {
        format: "keen-pbr-sb",
        version: 1,
        kind: "transports",
        transports: response.data,
      })
      toast.success(t("configTransfer.exported"))
    } catch (exportError) {
      toast.error(
        exportError instanceof Error
          ? exportError.message
          : t("configTransfer.exportFailed"),
        { richColors: true }
      )
    } finally {
      setTransportExportPending(false)
    }
  }
  const bypassMutation = usePostConfigMutation({
    mutation: {
      onSuccess: () => toast.success(t("transports.loopProtection.saved")),
      onError: (mutationError) =>
        toast.error(getApiErrorMessage(mutationError as ApiError), {
          richColors: true,
        }),
    },
  })
  const preferenceMutation = usePostConfigMutation({
    mutation: {
      onError: (mutationError) =>
        toast.error(getApiErrorMessage(mutationError as ApiError), {
          richColors: true,
        }),
    },
  })

  const addLoopProtection = (server: string) => {
    if (!keenConfig) return
    const bypassTag = "transport_bypass"
    const listName = "transport_servers"
    const existingBypass = (keenConfig.outbounds ?? []).find(
      (outbound) => outbound.tag === bypassTag
    )
    if (existingBypass && existingBypass.type !== "ignore") {
      toast.error(
        t("transports.loopProtection.tagConflict", { tag: bypassTag })
      )
      return
    }
    if (!window.confirm(t("transports.loopProtection.confirm", { server }))) {
      return
    }
    const existingList = keenConfig.lists?.[listName] ?? {}
    const isIp =
      server.includes(":") || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(server)
    const domains = new Set(existingList.domains ?? [])
    const ipCidrs = new Set(existingList.ip_cidrs ?? [])
    if (isIp) ipCidrs.add(server)
    else domains.add(server)
    const rules = keenConfig.route?.rules ?? []
    const hasRule = rules.some(
      (rule) => rule.outbound === bypassTag && rule.list?.includes(listName)
    )
    bypassMutation.mutate({
      data: {
        ...keenConfig,
        outbounds: existingBypass
          ? keenConfig.outbounds
          : [
              { type: "ignore", tag: bypassTag },
              ...(keenConfig.outbounds ?? []),
            ],
        lists: {
          ...keenConfig.lists,
          [listName]: {
            ...existingList,
            domains: [...domains],
            ip_cidrs: [...ipCidrs],
          },
        },
        route: {
          ...keenConfig.route,
          rules: hasRule
            ? rules
            : [{ list: [listName], outbound: bypassTag }, ...rules],
        },
      },
    })
  }

  const saveTransport = (
    spec: TransportSpec,
    options: { createOutbound: boolean }
  ) => {
    if (
      spec.display_name &&
      environmentQuery.data?.transport_api_version !== 2
    ) {
      toast.error(t("transports.form.backendUpdateRequired"), {
        richColors: true,
      })
      return
    }

    if (!editing && options.createOutbound) {
      configApplyMutation.mutate(
        { data: createLinkedTransportApplyRequest(spec) },
        {
          onSuccess: () => {
            setDialogOpen(false)
            setEditing(undefined)
            toast.success(t("transports.configMessages.create"))
          },
          onError: (mutationError) => {
            toast.error(getApiErrorMessage(mutationError), {
              richColors: true,
            })
          },
        }
      )
      return
    }

    configMutation.mutate({
      data: editing
        ? {
            operation: TransportConfigOperationOperation.update,
            tag: editing.tag,
            transport: spec,
          }
        : {
            operation: TransportConfigOperationOperation.create,
            transport: spec,
          },
    })
  }

  return (
    <div className="space-y-3">
      <PageHeader
        description={t("transports.description")}
        title={t("transports.title")}
      />
      <PageActionBar>
        <Button
          disabled={
            transferMutation.isPending ||
            transportExportPending ||
            configured.length === 0
          }
          onClick={() => void exportTransports()}
          variant="outline"
        >
          <DownloadIcon />
          {t("configTransfer.export")}
        </Button>
        <Button
          disabled={transferMutation.isPending}
          onClick={() => transportImportRef.current?.click()}
          variant="outline"
        >
          <UploadIcon />
          {t("configTransfer.import")}
        </Button>
        <input
          accept="application/json,.json"
          className="hidden"
          onChange={(event) => {
            const file = event.target.files?.[0]
            if (file) transferMutation.mutate(file)
          }}
          ref={transportImportRef}
          type="file"
        />
        <Button
          onClick={() => {
            setEditing(undefined)
            setDialogOpen(true)
          }}
        >
          <PlusIcon />
          {t("transports.add")}
        </Button>
        <Button
          disabled={
            query.isFetching ||
            ndmsInventoryQuery.isFetching ||
            runtimeInterfacesQuery.isFetching
          }
          onClick={() => {
            void query.refetch()
            void configQuery.refetch()
            void ndmsInventoryQuery.refetch()
            void runtimeInterfacesQuery.refetch()
          }}
          variant="outline"
        >
          <RefreshCwIcon
            className={
              query.isFetching ||
              ndmsInventoryQuery.isFetching ||
              runtimeInterfacesQuery.isFetching
                ? "animate-spin"
                : ""
            }
          />
          {t("transports.refresh")}
        </Button>
      </PageActionBar>

      {error ? (
        <Alert variant="destructive">
          <AlertTitle>{t("transports.unavailable")}</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}

      {environmentQuery.data?.sing_box_installed === false ? (
        <Alert variant="destructive">
          <AlertTitle>{t("transports.singBoxMissing.title")}</AlertTitle>
          <AlertDescription className="space-y-2">
            <p>{t("transports.singBoxMissing.description")}</p>
            <code className="block overflow-x-auto rounded bg-muted p-2 text-xs text-foreground">
              sh -c &quot;$(curl -fsSL
              https://raw.githubusercontent.com/blindtechnique/keen-pbr-sb/main/install.sh)&quot;
            </code>
          </AlertDescription>
        </Alert>
      ) : null}

      {needsNaiveComponent ? (
        <Alert variant="warning">
          <AlertTitle>{t("transports.naiveComponent.title")}</AlertTitle>
          <AlertDescription className="space-y-2">
            <p>{t("transports.naiveComponent.description")}</p>
            <Button
              disabled={naiveInstallMutation.isPending}
              onClick={() => naiveInstallMutation.mutate()}
              size="sm"
              variant="outline"
            >
              {naiveInstallMutation.isPending
                ? t("transports.naiveComponent.installing")
                : t("transports.naiveComponent.install")}
            </Button>
          </AlertDescription>
        </Alert>
      ) : null}

      {!query.isLoading &&
      !ndmsInventoryQuery.isLoading &&
      !error &&
      managedItems.length === 0 &&
      nativeInterfaces.length === 0 ? (
        <Card>
          <CardContent className="py-8 text-center text-muted-foreground">
            {t("transports.empty")}
          </CardContent>
        </Card>
      ) : null}

      {transportTabs.length > 1 ? (
        <SectionTabs
          ariaLabel={t("transports.tabs.ariaLabel")}
          onValueChange={setActiveTransportTab}
          tabs={transportTabs}
          value={activeTransportTab}
        />
      ) : null}
      {hiddenNativeCount > 0 ? (
        <div className="flex justify-end">
          <Button
            onClick={() => setShowHiddenNative((current) => !current)}
            size="sm"
            variant="ghost"
          >
            {showHiddenNative ? <EyeOffIcon /> : <EyeIcon />}
            {showHiddenNative
              ? t("transports.nativeInterface.hideHidden")
              : t("transports.nativeInterface.showHidden", {
                  count: hiddenNativeCount,
                })}
          </Button>
        </div>
      ) : null}

      <div className="grid items-start gap-4 lg:grid-cols-2">
        {visibleItems.map((item) => {
          const boundOutbound = interfaceOutboundByInterface.get(item.interface)
          const configuredSpec = configuredByTag.get(item.tag)
          const displayName =
            item.display_name?.trim() ||
            configuredSpec?.display_name?.trim() ||
            item.tag
          const expandedId = `managed:${item.tag}`
          const expanded = expandedTransportIds.has(expandedId)
          const transportPath = formatTransportPath(item)

          return (
            <Card
              className="flex min-w-0 flex-col overflow-hidden"
              key={item.tag}
              size="sm"
            >
              <CardHeader className="min-w-0 max-sm:grid-cols-1">
                <div className="min-w-0">
                  <CardTitle
                    className="leading-5 tracking-normal break-words"
                    title={item.tag}
                  >
                    {displayName}
                  </CardTitle>
                  <TransportIdentity
                    location={transportLocation(
                      configuredSpec,
                      locationOf(item.server)
                    )}
                    protocol={item.protocol || item.type}
                  />
                </div>
                <CardAction className="flex items-center gap-1 max-sm:col-start-1 max-sm:row-start-auto max-sm:w-full max-sm:justify-self-stretch">
                  <KeeneticStatus
                    tone={item.state === "up" ? "success" : "neutral"}
                  >
                    {t(`transports.states.${item.state}`)}
                  </KeeneticStatus>
                  {item.type !== "native" ? (
                    <Button
                      aria-label={t("transports.restart")}
                      className="size-7"
                      disabled={actionMutation.isPending}
                      onClick={() =>
                        actionMutation.mutate({
                          data: {
                            tag: item.tag,
                            action: TransportActionRequestAction.restart,
                          },
                        })
                      }
                      size="icon"
                      title={t("transports.restart")}
                      variant="ghost"
                    >
                      <RefreshCwIcon className="size-4" />
                    </Button>
                  ) : null}
                  {item.type !== "native" ? (
                    <Switch
                      aria-label={
                        item.desired_up
                          ? t("transports.stop")
                          : t("transports.start")
                      }
                      checked={item.desired_up}
                      disabled={actionMutation.isPending}
                      onCheckedChange={(checked) =>
                        actionMutation.mutate({
                          data: {
                            tag: item.tag,
                            action: checked
                              ? TransportActionRequestAction.up
                              : TransportActionRequestAction.down,
                          },
                        })
                      }
                    />
                  ) : null}
                  <Button
                    aria-expanded={expanded}
                    aria-label={
                      expanded
                        ? t("transports.details.hide")
                        : t("transports.details.show")
                    }
                    className="size-7 max-sm:ml-auto"
                    onClick={() => setTransportExpanded(expandedId, !expanded)}
                    size="icon"
                    title={
                      expanded
                        ? t("transports.details.hide")
                        : t("transports.details.show")
                    }
                    variant="ghost"
                  >
                    <ChevronDownIcon
                      className={cn(
                        "size-4 transition-transform",
                        expanded && "rotate-180"
                      )}
                    />
                  </Button>
                </CardAction>
              </CardHeader>
              {item.state === "up" ? (
                <div className="flex min-h-7 items-center px-3">
                  <TransportLatencyPill
                    onRefresh={() => refreshLatency(item.interface)}
                    probe={probeByInterface.get(item.interface)}
                    refreshing={latencyRefreshPending(item.interface)}
                    runtimeMilliseconds={transportLatencyByInterface.get(
                      item.interface
                    )}
                  />
                </div>
              ) : null}
              <CardContent
                className={cn(
                  "flex min-w-0 flex-1 flex-col gap-1.5 text-sm",
                  !expanded && "hidden"
                )}
              >
                {expanded ? (
                  <>
                    <TransportField
                      label={t("transports.interface")}
                      value={item.interface}
                    />
                    <TransportField
                      label={t("transports.server")}
                      value={
                        item.server
                          ? item.server_port
                            ? `${item.server}:${item.server_port}`
                            : item.server
                          : "—"
                      }
                    />
                    <div className="mt-1 flex min-w-0 flex-wrap items-center gap-1.5">
                      {transportPath ? (
                        <Badge
                          size="xs"
                          title={`${t("transports.pathConfidence")}: ${transportPath.confidence}`}
                          variant="outline"
                        >
                          {transportPath.text}
                        </Badge>
                      ) : null}
                      {dnsServersByInterface.has(item.interface) ? (
                        <Badge size="xs" variant="outline">
                          {t("transports.dnsDetour")}:{" "}
                          {(
                            dnsServersByInterface.get(item.interface) ?? []
                          ).join(", ")}
                        </Badge>
                      ) : null}
                      {item.type !== "native" && !item.desired_up ? (
                        <Badge size="xs" variant="secondary">
                          {t("transports.paused")}
                        </Badge>
                      ) : null}
                      {item.retry_count ? (
                        <Badge size="xs" variant="warning">
                          {t("transports.retryCount")}: {item.retry_count}
                        </Badge>
                      ) : null}
                    </div>

                    {item.error ? (
                      <p className="mt-1 rounded-md bg-destructive/10 p-2 text-xs text-destructive">
                        {item.error}
                      </p>
                    ) : null}

                    <InterfaceTraffic
                      labels={{
                        receive: t("transports.traffic.receive"),
                        transmit: t("transports.traffic.transmit"),
                        received: t("transports.traffic.received"),
                        transmitted: t("transports.traffic.transmitted"),
                        chart: t("transports.traffic.chart"),
                      }}
                      locale={i18n.resolvedLanguage ?? i18n.language}
                      showChart={false}
                      traffic={
                        runtimeInterfaceByName.get(item.interface)?.traffic
                      }
                    />

                    <div className="my-1 border-t" />
                    <TransportField
                      label={t("transports.connection")}
                      value={
                        describeConnection(item, transportPath?.text) || "—"
                      }
                    />
                    {item.type === "native" ? (
                      <p className="mt-1 text-xs text-muted-foreground">
                        {t("transports.nativeManagedExternally")}
                      </p>
                    ) : null}
                    <div className="mt-auto flex min-w-0 flex-wrap items-center gap-2 border-t pt-3">
                      {item.server ? (
                        <Button
                          className="h-auto max-w-full text-left whitespace-normal"
                          disabled={bypassMutation.isPending || !keenConfig}
                          onClick={() => addLoopProtection(item.server!)}
                          size="sm"
                          variant="outline"
                        >
                          <ShieldCheckIcon />
                          {t("transports.loopProtection.action")}
                        </Button>
                      ) : null}
                      <Button
                        className="h-auto max-w-full text-left whitespace-normal"
                        disabled={!keenConfig || Boolean(boundOutbound)}
                        onClick={() =>
                          navigate(
                            `/outbounds/create?type=interface&interface=${encodeURIComponent(item.interface)}`
                          )
                        }
                        size="sm"
                        title={
                          boundOutbound
                            ? t("transports.routing.alreadyBound", {
                                tag: boundOutbound.tag,
                              })
                            : t("transports.routing.bindOutbound")
                        }
                        variant="outline"
                      >
                        <WorkflowIcon />
                        {boundOutbound
                          ? t("transports.routing.alreadyBound", {
                              tag: boundOutbound.tag,
                            })
                          : t("transports.routing.bindOutbound")}
                      </Button>
                      {item.type !== "native" ? (
                        <span className="ml-auto flex shrink-0 items-center gap-1">
                          <Button
                            aria-label={t("common.edit")}
                            className="size-8"
                            onClick={() => {
                              const spec = configured.find(
                                (entry) => entry.tag === item.tag
                              )
                              if (spec) {
                                setEditing(spec)
                                setDialogOpen(true)
                              }
                            }}
                            size="icon"
                            title={t("common.edit")}
                            variant="ghost"
                          >
                            <PencilIcon className="size-4" />
                          </Button>
                          <Button
                            aria-label={t("common.delete")}
                            className="size-8 text-destructive hover:text-destructive"
                            onClick={() =>
                              setDeleting(
                                configured.find(
                                  (entry) => entry.tag === item.tag
                                )
                              )
                            }
                            size="icon"
                            title={t("common.delete")}
                            variant="ghost"
                          >
                            <TrashIcon className="size-4" />
                          </Button>
                        </span>
                      ) : null}
                    </div>
                  </>
                ) : null}
              </CardContent>
            </Card>
          )
        })}
        {visibleNativeInterfaces.map((nativeInterface) => {
          const boundOutbound = nativeInterface.kernelName
            ? interfaceOutboundByInterface.get(nativeInterface.kernelName)
            : undefined
          const expandedId = `native:${nativeInterface.id}`

          return (
            <NativeInterfaceCard
              boundOutboundTag={boundOutbound?.tag}
              expanded={expandedTransportIds.has(expandedId)}
              hasConfig={Boolean(keenConfig)}
              hidden={hiddenNativeIds.has(nativeInterface.id)}
              key={`keenetic:${nativeInterface.id}`}
              latencyMs={
                nativeInterface.kernelName
                  ? transportLatencyByInterface.get(nativeInterface.kernelName)
                  : undefined
              }
              latencyProbe={
                nativeInterface.kernelName
                  ? probeByInterface.get(nativeInterface.kernelName)
                  : undefined
              }
              nativeInterface={nativeInterface}
              onExpandedChange={(expanded) =>
                setTransportExpanded(expandedId, expanded)
              }
              onCreateRoute={(interfaceName) =>
                navigate(
                  `/outbounds/create?type=interface&interface=${encodeURIComponent(interfaceName)}`
                )
              }
              onHiddenChange={(hidden) =>
                setNativeHidden(nativeInterface.id, hidden)
              }
              onRefreshLatency={
                nativeInterface.kernelName && boundOutbound
                  ? () => refreshLatency(nativeInterface.kernelName!)
                  : undefined
              }
              refreshingLatency={
                nativeInterface.kernelName
                  ? latencyRefreshPending(nativeInterface.kernelName)
                  : false
              }
            />
          )
        })}
      </div>
      {dialogOpen ? (
        <TransportConfigDialog
          existingInterfaces={[
            ...configured.map((spec) => spec.interface),
            ...items.map((item) => item.interface),
            ...(keenConfig?.outbounds ?? []).flatMap((outbound) =>
              typeof outbound.interface === "string" ? [outbound.interface] : []
            ),
          ]}
          existingTags={[
            ...configured.map((spec) => spec.tag),
            ...items.map((item) => item.tag),
            ...(keenConfig?.outbounds ?? []).map((outbound) => outbound.tag),
          ]}
          initial={editing}
          isPending={configMutation.isPending || configApplyMutation.isPending}
          nativeCandidates={nativeTransportCandidates}
          onOpenChange={setDialogOpen}
          onSubmit={saveTransport}
          open
          singBoxAvailable={environmentQuery.data?.sing_box_installed !== false}
        />
      ) : null}
      <DeleteImpactDialog
        confirmLabel={t("common.delete")}
        description={t("transports.deleteDescription")}
        impactItems={deleting ? [{ label: deleting.tag }] : []}
        isPending={configMutation.isPending}
        onConfirm={() =>
          deleting &&
          configMutation.mutate({
            data: {
              operation: TransportConfigOperationOperation.delete,
              tag: deleting.tag,
            },
          })
        }
        onOpenChange={(open) => !open && setDeleting(undefined)}
        open={Boolean(deleting)}
        title={t("transports.deleteTitle")}
      />
    </div>
  )
}

function TransportIdentity({
  protocol,
  location,
}: {
  readonly protocol: string
  readonly location?: ServerLocation
}) {
  const flag = countryMark(location)

  return (
    <div className="mt-1 flex h-6 min-w-0 items-center gap-1.5">
      <TransportProtocolIcon protocol={protocol} />
      {flag ? (
        <span
          aria-label={location?.country ?? location?.country_code ?? ""}
          className="text-base leading-none"
          role="img"
          title={location?.country ?? location?.country_code ?? ""}
        >
          {flag}
        </span>
      ) : null}
    </div>
  )
}

function transportLocation(
  spec: TransportSpec | undefined,
  automatic: ServerLocation | undefined
): ServerLocation | undefined {
  if (spec?.geo_mode === "auto") return automatic
  if (spec?.geo_mode !== "manual" || !spec.country_code) return undefined
  return {
    country: spec.country ?? spec.country_code.toUpperCase(),
    country_code: spec.country_code,
  }
}

/**
 * Флаг страны.
 *
 * Собирается общим локальным helper из двухбуквенного кода, а не берётся у
 * сервиса. Это не зависит от того, доехало ли поле с эмодзи через все слои:
 * код страны короче и надёжнее.
 */
function countryMark(location?: ServerLocation): string {
  const code = location?.country_code?.trim().toUpperCase()
  return code
    ? countryFlag(code) || location?.emoji || ""
    : (location?.emoji ?? "")
}

/**
 * «Reality · ws · SNI example.com» — то, что раньше знала только ссылка.
 * Ничего из этого не секрет, но без этих трёх вещей по карточке нельзя
 * понять, чем именно отличаются два внешне одинаковых транспорта.
 */
function describeConnection(
  item: TransportStatus,
  pathDescription?: string
): string {
  const parts: string[] = []
  if (item.security) {
    parts.push(item.security === "reality" ? "Reality" : "TLS")
  }
  if (pathDescription) {
    parts.push(pathDescription)
  }
  if (item.sni && item.sni !== item.server) {
    parts.push(`SNI ${item.sni}`)
  }
  return parts.join(" · ")
}

function TransportField({ label, value }: { label: string; value: string }) {
  return (
    // Подпись занимает столько, сколько ей нужно, значение — весь остаток.
    // При равных долях длинное значение переносилось на вторую строку, хотя
    // место рядом пустовало, и соседние карточки переставали совпадать
    // строками. Однострочная высота задана здесь же, чтобы ряды двух карточек
    // стояли вровень независимо от длины значения.
    <div className="grid min-w-0 grid-cols-[auto_minmax(0,1fr)] items-baseline gap-4">
      <span className="min-w-0 whitespace-nowrap text-muted-foreground">
        {label}
      </span>
      <span className="min-w-0 truncate text-right font-mono" title={value}>
        {value}
      </span>
    </div>
  )
}

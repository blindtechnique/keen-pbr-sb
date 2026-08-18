import {
  ChevronDownIcon,
  PlusIcon,
  FolderInputIcon,
  FolderOutputIcon,
  EyeIcon,
  EyeOffIcon,
  RefreshCwIcon,
  Settings2Icon,
  ShieldCheckIcon,
  WandSparklesIcon,
  WorkflowIcon,
} from "lucide-react"
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react"
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
  usePostTransportActionMutation,
  usePostTransportConfigMutation,
  usePostConfigMutation,
} from "@/api/mutations"
import {
  getTransportRuntimeSettings,
  setTransportRuntimeSettings,
  transportRuntimeSettingsQueryKey,
  type SingBoxProcessMode,
  type TransportRuntimeSettings,
} from "@/api/transport-runtime-settings"
import {
  useGetConfig,
  useGetNdmsInterfaceInventory,
  useGetRuntimeInterfaces,
  useGetRuntimeOutbounds,
  useGetTransportConfig,
  useGetTransports,
} from "@/api/queries"
import { selectConfig } from "@/api/selectors"
import { KeenPencilIcon, KeenTrashIcon } from "@/components/shared/keen-icons"
import { DataTable } from "@/components/shared/data-table"
import { DeleteImpactDialog } from "@/components/shared/delete-impact-dialog"
import {
  buildUpdatedConfigForOutboundsDelete,
  getOutboundDeleteImpact,
} from "@/pages/outbounds-utils"
import { getOutboundDeleteImpactItems } from "@/components/delete-impact/outbound-items"
import { KeeneticStatus } from "@/components/shared/keenetic-status"
import { PageActionBar } from "@/components/shared/page-action-bar"
import { ListPlaceholder } from "@/components/shared/list-placeholder"
import { PageHeader } from "@/components/shared/page-header"
import { SectionHeading } from "@/components/shared/section-heading"
import { TableSkeleton } from "@/components/shared/table-skeleton"
import { SectionTabs, type SectionTab } from "@/components/shared/section-tabs"
import { NativeInterfaceDetails } from "@/components/transports/native-interface-details"
import { NativeRouteOffer } from "@/components/transports/native-route-offer"
import { InterfaceTraffic } from "@/components/transports/interface-traffic"
import { TransportLatencyPill } from "@/components/transports/transport-latency-pill"
import { transportOperationalState } from "@/components/transports/transport-operational-state"
import {
  collectProbeByInterface,
  collectRuntimeLatencyByInterface,
} from "@/components/transports/transport-latency-model"
import { TransportProtocolIcon } from "@/components/transports/protocol-icon"
import {
  describeTransportWire,
  formatTransportPath,
} from "@/components/transports/transport-path"
import { SingBoxProcessModeDialog } from "@/components/transports/sing-box-process-mode-dialog"
import { SingBoxInstallButton } from "@/components/transports/sing-box-install-button"
import { TransportExitCheckButton } from "@/components/transports/exit-check-button"
import { transportErrorText } from "@/components/transports/transport-error-model"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { DependencyList } from "@/components/shared/dependency-list"
import type { Dependency } from "@/lib/dependencies"
import { Badge } from "@/components/ui/badge"
import { Switch } from "@/components/ui/switch"
import { Button } from "@/components/ui/button"
import { getApiErrorMessage } from "@/lib/api-errors"
import { getOutboundDisplayName } from "@/lib/outbound-display"
import {
  dismissNativeRouteOffer,
  pickNativeRouteOfferCandidates,
  readDismissedNativeRouteOffers,
  type NativeRouteOfferCandidate,
} from "@/lib/native-route-offers"
import { makeTechnicalId } from "@/lib/technical-id"
import {
  useServerLocations,
  type ServerLocation,
} from "@/hooks/use-server-locations"
import { useRunSystemProbes } from "@/hooks/use-run-system-probes"
import { cn } from "@/lib/utils"
import { downloadJson, formatDownloadTimestamp } from "@/lib/download"
import { queryKeys } from "@/api/query-keys"
import { countryFlag } from "@/data/countries"
import { useConfigDependencies } from "@/hooks/use-config-dependencies"
import { useSectionTab } from "@/hooks/use-section-tab"
import {
  buildTransportEditHref,
  transportCreateHref,
} from "@/lib/transport-upsert-route"
import {
  dedupeLegacyNativeTransports,
  mapNativeInterfaces,
  type NativeInterfaceModel,
} from "@/lib/native-interfaces"
import {
  getHiddenNativeInterfaceIds,
  updateHiddenNativeInterfacePreference,
} from "@/lib/hidden-native-interfaces"

type ProbeEntry = {
  success: boolean
  // Absent on daemons that predate probe attribution; treated as unattributed.
  attributed?: boolean
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

/**
 * AWG и WG — одна вкладка, а не две. Решение владельца: сюда попадают
 * AWG/WG-туннели из KeeneticOS, и сюда же лягут туннели, которые keen-pbr-sb
 * научится создавать сам. Раздельные вкладки AmneziaWG/WireGuard дробили
 * одну и ту же семью протоколов, а NDMS к тому же не всегда отличает их
 * друг от друга.
 */
const AWG_WG_TAB = "amnezia-wireguard"
const AWG_WG_LABEL = "Amnezia (WireGuard)"

const WIREGUARD_NDMS_KINDS = new Set(["amnezia_wireguard", "wireguard"])

function isWireguardNative(nativeInterface: NativeInterfaceModel): boolean {
  return WIREGUARD_NDMS_KINDS.has(nativeInterface.source.kind)
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
    return { key: AWG_WG_TAB, label: AWG_WG_LABEL }
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
    return { key: AWG_WG_TAB, label: AWG_WG_LABEL }
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

export function TransportsPage({
  embedded = false,
}: { embedded?: boolean } = {}) {
  const queryClient = useQueryClient()
  const { t, i18n } = useTranslation()
  const [, navigate] = useLocation()
  const [processModeDialogOpen, setProcessModeDialogOpen] = useState(false)
  const [selectedProcessMode, setSelectedProcessMode] =
    useState<SingBoxProcessMode>("isolated")
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
  // «Не предлагать» из вопроса о новом туннеле; читается один раз при
  // открытии страницы, дальше живёт в состоянии и localStorage.
  const [dismissedRouteOffers, setDismissedRouteOffers] = useState<Set<string>>(
    () => readDismissedNativeRouteOffers()
  )
  const transportImportRef = useRef<HTMLInputElement>(null)
  const query = useGetTransports({
    query: {
      refetchInterval: 3_000,
      refetchIntervalInBackground: false,
    },
  })
  const processModeQuery = useQuery({
    queryKey: transportRuntimeSettingsQueryKey,
    queryFn: getTransportRuntimeSettings,
    retry: false,
    refetchOnWindowFocus: false,
    staleTime: 30_000,
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
  const displayedNativeInterfaces = nativeInterfaces.filter(
    (nativeInterface) =>
      showHiddenNative || !hiddenNativeIds.has(nativeInterface.id)
  )
  const providerGroups = useMemo(
    () => groupTransports(managedItems, t("transports.tabs.other")),
    [managedItems, t]
  )
  const nativeWgInterfaces = useMemo(
    () => displayedNativeInterfaces.filter(isWireguardNative),
    [displayedNativeInterfaces]
  )
  const otherNativeCount =
    displayedNativeInterfaces.length - nativeWgInterfaces.length
  const transportTabs = useMemo<SectionTab<string>[]>(() => {
    const providerTabs = providerGroups.map((group) => ({
      value: group.key,
      label: group.label,
      count: group.items.length,
    }))
    // Вкладки KeeneticOS больше нет: AWG/WG-интерфейсы прошивки живут на
    // общей вкладке Amnezia (WireGuard), остальные нативные — только в «Все».
    if (nativeWgInterfaces.length > 0) {
      const awgTab = providerTabs.find((tab) => tab.value === AWG_WG_TAB)
      if (awgTab) {
        awgTab.count += nativeWgInterfaces.length
      } else {
        providerTabs.push({
          value: AWG_WG_TAB,
          label: AWG_WG_LABEL,
          count: nativeWgInterfaces.length,
        })
      }
    }

    // «Все» нужна и тогда, когда вкладка одна, но есть нативные интерфейсы
    // без своей вкладки (OpenVPN, L2TP…): иначе их не было бы видно нигде.
    return providerTabs.length > 1 ||
      (providerTabs.length > 0 && otherNativeCount > 0)
      ? [
          {
            value: "all",
            label: t("transports.tabs.all"),
            count: managedItems.length + displayedNativeInterfaces.length,
          },
          ...providerTabs,
        ]
      : providerTabs
  }, [
    displayedNativeInterfaces.length,
    managedItems.length,
    nativeWgInterfaces.length,
    otherNativeCount,
    providerGroups,
    t,
  ])
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
    activeTransportTab === "all"
      ? displayedNativeInterfaces
      : activeTransportTab === AWG_WG_TAB
        ? nativeWgInterfaces
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
    // The tag of the outbound bound to this interface, so the daemon measures
    // this row and nothing else. Falling back to the whole round when the
    // interface has no bound outbound keeps the button working rather than
    // making it silently do nothing.
    const boundTag = (keenConfig?.outbounds ?? []).find(
      (outbound) =>
        outbound.type === "interface" && outbound.interface === interfaceName
    )?.tag
    runProbeMutation.mutate(boundTag, {
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
  // Вопрос «использовать новый туннель как VPN?»: владелец добавляет AWG в
  // KeeneticOS и ждёт, что keen-pbr-sb сам предложит привязать маршрут.
  // Спрашиваем только когда конфигурация загружена: иначе на мгновение
  // возник бы вопрос про туннели, маршруты которых ещё не приехали.
  const routeOfferCandidates = keenConfig
    ? pickNativeRouteOfferCandidates({
        nativeInterfaces,
        boundInterfaceNames: new Set(interfaceOutboundByInterface.keys()),
        hiddenIds: hiddenNativeIds,
        dismissedIds: dismissedRouteOffers,
      })
    : []
  // Что реально ходит через этот транспорт. Транспорт создаёт интерфейс, на
  // интерфейс смотрит маршрут, а за маршрут держатся правила, списки и DNS —
  // ту же цепочку показывает страница маршрутов, здесь её просто не было.
  const transportDependencyTargets = useMemo(
    () =>
      [
        ...new Set(
          (keenConfig?.outbounds ?? [])
            .filter(
              (outbound) =>
                outbound.type === "interface" &&
                typeof outbound.interface === "string" &&
                outbound.interface.length > 0
            )
            .map((outbound) => outbound.tag)
        ),
      ].map((tag) => ({ kind: "outbound" as const, id: tag })),
    [keenConfig]
  )
  const transportDependencies = useConfigDependencies(
    keenConfig,
    transportDependencyTargets
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
  const runtimeOutboundByTag = new Map(
    (runtimeOutboundsQuery.data?.status === 200
      ? runtimeOutboundsQuery.data.data.outbounds
      : []
    ).map((runtimeOutbound) => [runtimeOutbound.tag, runtimeOutbound])
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
  const processModeMutation = useMutation<
    TransportRuntimeSettings,
    ApiError,
    SingBoxProcessMode
  >({
    mutationFn: setTransportRuntimeSettings,
    onSuccess: async (settings) => {
      queryClient.setQueryData(transportRuntimeSettingsQueryKey, settings)
      setSelectedProcessMode(settings.sing_box_process_mode)
      setProcessModeDialogOpen(false)
      await Promise.all([
        queryClient.invalidateQueries({
          queryKey: queryKeys.transports(),
        }),
        queryClient.invalidateQueries({
          queryKey: queryKeys.runtimeInterfaces(),
        }),
        queryClient.invalidateQueries({
          queryKey: queryKeys.runtimeOutbounds(),
        }),
        queryClient.invalidateQueries({
          queryKey: queryKeys.healthService(),
        }),
      ])
      toast.success(t("transports.processMode.applied"))
    },
    onError: (mutationError) => {
      toast.error(getApiErrorMessage(mutationError), {
        richColors: true,
      })
    },
  })
  // Удаление маршрута перед удалением туннеля. Порядок сознательный: маршрут
  // уходит в черновик конфигурации (ничего не меняя на роутере до apply), и
  // только после этого туннель удаляется по-настоящему. В обратном порядке
  // упавший второй шаг оставил бы правила, ведущие в несуществующий туннель.
  // Атомарной пары операций в API пока нет — это отмечено Codex в changelog.
  const routeDeleteMutation = usePostConfigMutation()
  const configMutation = usePostTransportConfigMutation({
    mutation: {
      onSuccess: (_data, variables) => {
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
  const routeOfferMutation = usePostConfigMutation({
    mutation: {
      onError: (mutationError) =>
        toast.error(getApiErrorMessage(mutationError as ApiError), {
          richColors: true,
        }),
    },
  })

  // «Да» из вопроса о новом туннеле: маршрут создаётся сразу, с настройками
  // по умолчанию — имя от туннеля, тег порождается из имени. Тонкая
  // настройка (kill-switch, шлюзы) остаётся в редакторе маршрута.
  const createRouteFromOffer = (candidate: NativeRouteOfferCandidate) => {
    if (!keenConfig) return
    const existingOutbounds = keenConfig.outbounds ?? []
    const tag = makeTechnicalId(
      candidate.label,
      existingOutbounds.map((outbound) => outbound.tag),
      { prefix: "outbound" }
    )
    routeOfferMutation.mutate(
      {
        data: {
          ...keenConfig,
          outbounds: [
            ...existingOutbounds,
            {
              type: "interface",
              tag,
              display_name: candidate.label,
              interface: candidate.interfaceName,
            },
          ],
        },
      },
      {
        onSuccess: () =>
          toast.success(
            t("transports.routeOffer.created", { name: candidate.label })
          ),
      }
    )
  }
  const dismissRouteOffer = (candidate: NativeRouteOfferCandidate) => {
    setDismissedRouteOffers((current) =>
      dismissNativeRouteOffer(candidate.id, current)
    )
  }

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

  // Список туннелей — таблица, а не карточки. Строка отвечает на «что это,
  // работает ли и кто на нём держится», подробности раскрываются под строкой.
  // Карточками та же запись занимала около 120px, и семь туннелей не влезали
  // на экран целиком — при том что сравнивают их постоянно: задержки, состояния
  // и привязку удобно читать столбцом, а не перечитывая семь карточек.
  const transportTableHeaders = [
    // Колонка управления идёт без названия — как в таблицах прошивки. На
    // телефоне DataTable по этому и понимает, что переключатель нужно поднять
    // в строку кнопок, а не показывать отдельным блоком.
    "",
    t("transports.headers.name"),
    t("transports.headers.state"),
    t("transports.headers.latency"),
    t("transports.headers.usedBy"),
    t("transports.headers.actions"),
  ]

  const managedRows = visibleItems.map((item) => {
    const boundOutbound = interfaceOutboundByInterface.get(item.interface)
    const operationalState = transportOperationalState(
      item,
      boundOutbound ? runtimeOutboundByTag.get(boundOutbound.tag) : undefined,
      Boolean(boundOutbound)
    )
    const configuredSpec = configuredByTag.get(item.tag)
    const displayName =
      item.display_name?.trim() ||
      configuredSpec?.display_name?.trim() ||
      item.tag
    const expandedId = `managed:${item.tag}`
    const expanded = expandedTransportIds.has(expandedId)
    const transportPath = formatTransportPath(item)
    const isNative = item.type === "native"

    const cells: ReactNode[] = [
      <span className="flex items-center gap-1" key="power">
        <Switch
          aria-label={
            item.desired_up ? t("transports.stop") : t("transports.start")
          }
          checked={isNative ? true : item.desired_up}
          disabled={isNative || actionMutation.isPending}
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
          title={
            isNative
              ? t("transports.nativeInterface.managedByFirmware")
              : undefined
          }
        />
        <Button
          aria-label={t("transports.restart")}
          className="size-7"
          disabled={isNative || actionMutation.isPending}
          onClick={() =>
            actionMutation.mutate({
              data: {
                tag: item.tag,
                action: TransportActionRequestAction.restart,
              },
            })
          }
          size="icon"
          title={
            isNative
              ? t("transports.nativeInterface.managedByFirmware")
              : t("transports.restart")
          }
          variant="ghost"
        >
          <RefreshCwIcon className="size-4" />
        </Button>
      </span>,
      <TransportName
        key="name"
        location={transportLocation(configuredSpec, locationOf(item.server))}
        name={displayName}
        protocol={item.protocol || item.type}
        technicalTag={item.tag}
        wire={describeTransportWire(item)}
      />,
      <KeeneticStatus
        key="state"
        title={operationalState.detail}
        tone={operationalState.healthy ? "success" : "neutral"}
      >
        {t(`transports.operationalStates.${operationalState.key}`)}
      </KeeneticStatus>,
      <TransportLatencyPill
        key="latency"
        onRefresh={() => refreshLatency(item.interface)}
        probe={probeByInterface.get(item.interface)}
        refreshing={latencyRefreshPending(item.interface)}
        runtimeMilliseconds={transportLatencyByInterface.get(item.interface)}
      />,
      <UsedByCell
        bound={Boolean(boundOutbound)}
        dependencies={
          boundOutbound
            ? transportDependencies.dependenciesByTarget.get(
                `outbound:${boundOutbound.tag}`
              )
            : undefined
        }
        key="usedBy"
        selfNames={
          boundOutbound
            ? [getOutboundDisplayName(boundOutbound), boundOutbound.tag]
            : []
        }
      />,
      <RowActions
        deleteDisabled={isNative}
        deleteTitle={
          isNative
            ? t("transports.nativeInterface.managedByFirmware")
            : t("common.delete")
        }
        editDisabled={isNative}
        editTitle={
          isNative
            ? t("transports.nativeInterface.managedByFirmware")
            : t("common.edit")
        }
        expanded={expanded}
        key="actions"
        onDelete={() =>
          setDeleting(configured.find((entry) => entry.tag === item.tag))
        }
        onEdit={() => navigate(buildTransportEditHref(item.tag))}
        onToggleExpanded={() => setTransportExpanded(expandedId, !expanded)}
        toggleTitle={
          expanded ? t("transports.details.hide") : t("transports.details.show")
        }
      />,
    ]

    const errorText = transportErrorText(item.error)
    const details = expanded ? (
      <div className="space-y-3 text-sm">
        <div className="grid min-w-0 gap-x-8 gap-y-1.5 sm:grid-cols-2">
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
          {/* Техническое имя интерфейса живёт здесь, а не в строке: оно выдано
              ядром и нужно, только когда человек лезет в подробности. */}
          <TransportField
            label={t("transports.interfaceName")}
            value={item.interface || "—"}
          />
          <TransportField
            label={t("transports.connection")}
            value={describeConnection(item, transportPath?.text) || "—"}
          />
        </div>

        {dnsServersByInterface.has(item.interface) ||
        (!isNative && !item.desired_up) ||
        item.retry_count ? (
          <div className="flex min-w-0 flex-wrap items-center gap-1.5">
            {dnsServersByInterface.has(item.interface) ? (
              <Badge size="xs" variant="outline">
                {t("transports.dnsDetour")}:{" "}
                {(dnsServersByInterface.get(item.interface) ?? []).join(", ")}
              </Badge>
            ) : null}
            {!isNative && !item.desired_up ? (
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
        ) : null}

        {/* Надзиратель отдаёт причину одной непрозрачной английской строкой,
            собранной как «keen-pbr routing health: <вердикт>: <деталь>».
            Имя внутреннего компонента оператору ничего не говорит, а сама
            деталь у панели уже переведена — но выбросить абзац нельзя, это
            единственное место, где причина вообще видна. Поэтому: узнать
            форму, перевести знакомое, незнакомое пропустить как есть. */}
        {errorText ? (
          <p className="rounded-md bg-destructive/10 p-2 text-xs text-destructive">
            {errorText.kind === "issue"
              ? t(`overview.outbounds.issue.${errorText.code}`)
              : errorText.text}
          </p>
        ) : null}

        <InterfaceTraffic
          labels={{
            receive: t("transports.traffic.receive"),
            transmit: t("transports.traffic.transmit"),
            received: t("transports.traffic.received"),
            transmitted: t("transports.traffic.transmitted"),
            chart: t("transports.traffic.chart"),
            noTraffic: t("transports.traffic.noTraffic"),
            stale: t("transports.traffic.stale"),
          }}
          locale={i18n.resolvedLanguage ?? i18n.language}
          // График живёт только на дашборде: рядом с цепочкой зависимостей он
          // раздувал раскрытую часть на пол-экрана, а для сравнения туннелей
          // между собой в таблице уже есть колонка задержки.
          showChart={false}
          traffic={runtimeInterfaceByName.get(item.interface)?.traffic}
        />

        {boundOutbound ? (
          // Ответ на «кто этим пользуется» по всем четырём категориям сразу —
          // правила, DNS-серверы, списки, группы, — а не только по тем, где
          // связи нашлись: пустая категория с «-» тоже ответ.
          <DependencyList
            dependencies={trimSelfRouteSuffix(
              transportDependencies.dependenciesByTarget.get(
                `outbound:${boundOutbound.tag}`
              ),
              [getOutboundDisplayName(boundOutbound), boundOutbound.tag]
            )}
            fixedKinds={TUNNEL_USAGE_KINDS}
          />
        ) : null}

        <div className="flex min-w-0 flex-wrap items-center gap-2">
          {/* Рядом с остальными действиями подключения: их нажимают в одном и
              том же случае — когда с конкретным туннелем что-то не так. */}
          <TransportExitCheckButton
            device={boundOutbound ? undefined : item.interface}
            outbound={boundOutbound?.tag}
          />
          {item.server ? (
            <Button
              disabled={bypassMutation.isPending || !keenConfig}
              onClick={() => addLoopProtection(item.server!)}
              variant="outline"
            >
              <ShieldCheckIcon />
              {t("transports.loopProtection.action")}
            </Button>
          ) : null}
          {/* Раньше здесь стояла мёртвая кнопка «Уже привязан к X» — она
              повторяла то, что теперь написано в колонке, и ничего не делала.
              Если привязка есть, кнопка ведёт к этому маршруту. */}
          <Button
            disabled={!keenConfig}
            onClick={() =>
              navigate(
                boundOutbound
                  ? // Тонкая настройка маршрута — только в расширенном
                    // редакторе (решение владельца): диалог туннеля остаётся
                    // простым, а kill-switch и шлюзы живут на полной странице.
                    `/outbounds/${encodeURIComponent(boundOutbound.tag)}/edit?view=page`
                  : `/outbounds/create?type=interface&interface=${encodeURIComponent(item.interface)}`
              )
            }
            variant="outline"
          >
            <WorkflowIcon />
            {boundOutbound
              ? t("transports.routing.openOutbound")
              : t("transports.routing.bindOutbound")}
          </Button>
        </div>

        {isNative ? (
          <p className="text-xs text-muted-foreground">
            {t("transports.nativeManagedExternally")}
          </p>
        ) : null}
      </div>
    ) : undefined

    return { cells, details }
  })

  const nativeRows = visibleNativeInterfaces.map((nativeInterface) => {
    const boundOutbound = nativeInterface.kernelName
      ? interfaceOutboundByInterface.get(nativeInterface.kernelName)
      : undefined
    const expandedId = `native:${nativeInterface.id}`
    const expanded = expandedTransportIds.has(expandedId)
    const latencyMs = nativeInterface.kernelName
      ? transportLatencyByInterface.get(nativeInterface.kernelName)
      : undefined
    const showLatency =
      nativeInterface.live &&
      (typeof latencyMs === "number" || Boolean(boundOutbound))
    const firmwareTitle = t("transports.nativeInterface.managedByFirmware")

    const cells: ReactNode[] = [
      // Выключателем и перезапуском этими интерфейсами управляет прошивка,
      // поэтому кнопки неактивны — но место занято, иначе колонки разъезжаются.
      <span className="flex items-center gap-1" key="power">
        <Switch
          aria-label={firmwareTitle}
          checked={nativeInterface.live}
          disabled
          title={firmwareTitle}
        />
        <Button
          aria-label={t("transports.restart")}
          className="size-7"
          disabled
          size="icon"
          title={firmwareTitle}
          variant="ghost"
        >
          <RefreshCwIcon className="size-4" />
        </Button>
      </span>,
      <span className="flex min-w-0 items-center gap-2" key="name">
        <TransportProtocolIcon protocol={nativeInterface.protocol.label} />
        {/* Пол в 6rem: в тесной колонке имя сжималось до нуля, и от строки
            оставался один бейдж KeeneticOS — без имени он ни о чём. */}
        <span className="min-w-[6rem] truncate" title={nativeInterface.label}>
          {nativeInterface.label}
        </span>
        <Badge className="shrink-0" size="xs" variant="secondary">
          {t("transports.nativeInterface.keeneticOwner")}
        </Badge>
      </span>,
      <KeeneticStatus
        key="state"
        title={
          nativeInterface.runtime
            ? undefined
            : t("transports.nativeInterface.liveUnavailable")
        }
        tone={nativeInterface.live ? "success" : "neutral"}
      >
        {nativeInterface.runtime
          ? nativeInterface.live
            ? t("transports.nativeInterface.connected")
            : t("transports.nativeInterface.disconnected")
          : t("transports.nativeInterface.liveUnavailableShort")}
      </KeeneticStatus>,
      showLatency ? (
        <TransportLatencyPill
          key="latency"
          onRefresh={
            nativeInterface.kernelName && boundOutbound
              ? () => refreshLatency(nativeInterface.kernelName!)
              : undefined
          }
          probe={
            nativeInterface.kernelName
              ? probeByInterface.get(nativeInterface.kernelName)
              : undefined
          }
          refreshing={
            nativeInterface.kernelName
              ? latencyRefreshPending(nativeInterface.kernelName)
              : false
          }
          runtimeMilliseconds={
            typeof latencyMs === "number" &&
            Number.isFinite(latencyMs) &&
            latencyMs >= 0
              ? latencyMs
              : undefined
          }
        />
      ) : null,
      <UsedByCell
        bound={Boolean(boundOutbound)}
        dependencies={
          boundOutbound
            ? transportDependencies.dependenciesByTarget.get(
                `outbound:${boundOutbound.tag}`
              )
            : undefined
        }
        key="usedBy"
        selfNames={
          boundOutbound
            ? [getOutboundDisplayName(boundOutbound), boundOutbound.tag]
            : []
        }
      />,
      <RowActions
        deleteDisabled
        deleteTitle={firmwareTitle}
        editDisabled
        editTitle={firmwareTitle}
        expanded={expanded}
        key="actions"
        onDelete={() => undefined}
        onEdit={() => undefined}
        onToggleExpanded={() => setTransportExpanded(expandedId, !expanded)}
        toggleTitle={
          expanded ? t("transports.details.hide") : t("transports.details.show")
        }
      />,
    ]

    const details = expanded ? (
      <NativeInterfaceDetails
        boundOutboundTag={boundOutbound?.tag}
        hasConfig={Boolean(keenConfig)}
        hidden={hiddenNativeIds.has(nativeInterface.id)}
        nativeInterface={nativeInterface}
        onCreateRoute={(interfaceName) =>
          navigate(
            `/outbounds/create?type=interface&interface=${encodeURIComponent(interfaceName)}`
          )
        }
        onHiddenChange={(hidden) => setNativeHidden(nativeInterface.id, hidden)}
        usage={
          boundOutbound ? (
            <DependencyList
              dependencies={trimSelfRouteSuffix(
                transportDependencies.dependenciesByTarget.get(
                  `outbound:${boundOutbound.tag}`
                ),
                [getOutboundDisplayName(boundOutbound), boundOutbound.tag]
              )}
              fixedKinds={TUNNEL_USAGE_KINDS}
            />
          ) : undefined
        }
      />
    ) : undefined

    return { cells, details }
  })

  // Маршруты без туннеля. По новой модели их быть не должно — маршрут
  // создаётся вместе с туннелем, — но чужой tun0 из другого пакета Entware
  // никуда не делся. Отдельного блока «Прочие маршруты» владелец не захотел,
  // поэтому такие маршруты стоят строками в общем списке, честно подписанные.
  //
  // Привязка считается от ВСЕХ туннелей и интерфейсов, а не от видимых на
  // текущей вкладке: маршрут выключенного туннеля принадлежит его строке, а
  // спрятанный интерфейс прошивки не делает свой маршрут «сиротой». Иначе
  // переключение вкладки-провайдера превращало чужие туннели в «сирот».
  const linkedOutboundTags = new Set<string>()
  for (const item of managedItems) {
    const bound = interfaceOutboundByInterface.get(item.interface)
    if (bound) linkedOutboundTags.add(bound.tag)
    linkedOutboundTags.add(item.tag)
  }
  for (const spec of configured) {
    const bound = interfaceOutboundByInterface.get(spec.interface)
    if (bound) linkedOutboundTags.add(bound.tag)
    linkedOutboundTags.add(spec.tag)
  }
  for (const nativeInterface of nativeInterfaces) {
    const bound = nativeInterface.kernelName
      ? interfaceOutboundByInterface.get(nativeInterface.kernelName)
      : undefined
    if (bound) linkedOutboundTags.add(bound.tag)
  }
  // Члены групп «сиротами» не считаются: их видно в составе группы, и
  // показывать их ещё раз отдельными строками — тот же дубль, от которого
  // владелец избавлялся, сливая туннели с маршрутами.
  const groupMemberTags = new Set<string>()
  for (const outbound of keenConfig?.outbounds ?? []) {
    if (outbound.type !== "urltest") continue
    for (const group of outbound.outbound_groups ?? []) {
      for (const member of group.outbounds) groupMemberTags.add(member)
    }
  }
  const orphanOutbounds = (keenConfig?.outbounds ?? []).filter(
    (outbound) =>
      outbound.type === "interface" &&
      !linkedOutboundTags.has(outbound.tag) &&
      !groupMemberTags.has(outbound.tag)
  )
  const orphanRows = orphanOutbounds.map((outbound) => {
    const runtimeInterface = runtimeInterfaceByName.get(
      outbound.interface ?? ""
    )
    const editHref = `/outbounds/${encodeURIComponent(outbound.tag)}/edit?view=page`
    const cells: ReactNode[] = [
      <span key="power" />,
      <span className="flex min-w-0 flex-col" key="name">
        <span className="truncate text-sm font-medium">
          {outbound.display_name?.trim() || outbound.tag}
        </span>
        <span className="truncate font-mono text-xs text-muted-foreground">
          {outbound.interface}
        </span>
      </span>,
      <KeeneticStatus
        key="state"
        tone={runtimeInterface?.status === "up" ? "success" : "neutral"}
      >
        {runtimeInterface
          ? runtimeInterface.status === "up"
            ? t("pages.settings.general.inboundInterfacesStatusUp")
            : t("pages.settings.general.inboundInterfacesStatusDown")
          : t("runtime.outboundStatus.unknown")}
      </KeeneticStatus>,
      <span className="text-xs text-muted-foreground" key="latency">
        —
      </span>,
      <UsedByCell
        bound
        dependencies={transportDependencies.dependenciesByTarget.get(
          `outbound:${outbound.tag}`
        )}
        key="usedBy"
        selfNames={[getOutboundDisplayName(outbound), outbound.tag]}
      />,
      <span
        className="keen-row-actions ml-auto inline-flex justify-end gap-2"
        key="actions"
      >
        <Button
          aria-label={t("transports.routing.openOutbound")}
          className="keen-row-action size-8 rounded-[4px]"
          onClick={() => navigate(editHref)}
          size="icon"
          title={t("transports.routing.openOutbound")}
          variant="outline"
        >
          <KeenPencilIcon className="size-4" />
        </Button>
      </span>,
    ]
    return { cells, details: undefined as ReactNode }
  })

  const transportRows = [...managedRows, ...nativeRows, ...orphanRows]
  // Маршрут, связанный с удаляемым туннелем: по интерфейсу либо по тегу.
  const deletingLinkedOutbound = deleting
    ? (interfaceOutboundByInterface.get(deleting.interface) ??
      keenConfig?.outbounds?.find(
        (outbound) =>
          outbound.type === "interface" && outbound.tag === deleting.tag
      ))
    : undefined

  const transportRowDetails: Record<number, ReactNode> = {}
  for (const [index, row] of transportRows.entries()) {
    if (row.details) transportRowDetails[index] = row.details
  }
  // Подписи «свои туннели» / «интерфейсы прошивки» убраны по решению
  // владельца: список общий, происхождение туннеля видно по вкладкам и по
  // недоступным действиям. Единственная оставшаяся подпись — честное
  // предупреждение про маршруты без туннеля.
  const transportGroupHeadings: Record<number, ReactNode> = {}
  if (orphanRows.length > 0) {
    transportGroupHeadings[managedRows.length + nativeRows.length] = (
      <SectionHeading
        description={t("transports.groups.orphanDescription")}
        size="compact"
        title={t("transports.groups.orphan")}
      />
    )
  }

  return (
    <div className="space-y-3">
      {embedded ? null : (
        <PageHeader
          description={t("transports.description")}
          title={t("transports.title")}
        />
      )}
      <PageActionBar
        primary={
          <Button onClick={() => navigate(transportCreateHref)}>
            <PlusIcon />
            {t("transports.add")}
          </Button>
        }
      >
        <Button onClick={() => navigate("/setup")} variant="outline">
          <WandSparklesIcon />
          {t("transports.setupWizard")}
        </Button>
        {/* One control for the binary every transport on this page runs on.
            It reads Install, Update, or nothing-to-do, and says which in its
            tooltip - there is no card and no menu entry, because sing-box is
            a dependency rather than a thing an operator manages. */}
        <SingBoxInstallButton className="w-full sm:w-auto" variant="outline" />
        <Button
          disabled={
            transferMutation.isPending ||
            transportExportPending ||
            configured.length === 0
          }
          onClick={() => void exportTransports()}
          variant="outline"
        >
          <FolderOutputIcon />
          {t("configTransfer.export")}
        </Button>
        <Button
          disabled={transferMutation.isPending}
          onClick={() => transportImportRef.current?.click()}
          variant="outline"
        >
          <FolderInputIcon />
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
          aria-describedby={
            processModeQuery.isError
              ? "transport-process-mode-unavailable"
              : undefined
          }
          disabled={
            processModeQuery.isPending ||
            processModeQuery.isError ||
            !processModeQuery.data ||
            processModeMutation.isPending
          }
          onClick={() => {
            const settings = processModeQuery.data
            if (!settings) return
            setSelectedProcessMode(settings.sing_box_process_mode)
            setProcessModeDialogOpen(true)
          }}
          title={
            processModeQuery.isError
              ? t("transports.processMode.unavailable")
              : undefined
          }
          variant="outline"
        >
          <Settings2Icon />
          {t("transports.processMode.action")}
        </Button>
        {processModeQuery.isError ? (
          <span className="sr-only" id="transport-process-mode-unavailable">
            {t("transports.processMode.unavailable")}
          </span>
        ) : null}
        <Button
          disabled={
            query.isFetching ||
            ndmsInventoryQuery.isFetching ||
            runtimeInterfacesQuery.isFetching ||
            processModeQuery.isFetching
          }
          onClick={() => {
            void query.refetch()
            void configQuery.refetch()
            void ndmsInventoryQuery.refetch()
            void runtimeInterfacesQuery.refetch()
            void processModeQuery.refetch()
          }}
          variant="outline"
        >
          <RefreshCwIcon
            className={
              query.isFetching ||
              ndmsInventoryQuery.isFetching ||
              runtimeInterfacesQuery.isFetching ||
              processModeQuery.isFetching
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
            <code className="block rounded bg-muted p-2 text-xs break-all text-foreground">
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
        <ListPlaceholder
          action={
            <span className="flex flex-wrap justify-center gap-2">
              <Button onClick={() => navigate("/setup")}>
                <WandSparklesIcon className="mr-1 h-4 w-4" />
                {t("transports.setupWizard")}
              </Button>
              <Button
                onClick={() => navigate(transportCreateHref)}
                variant="outline"
              >
                <PlusIcon className="mr-1 h-4 w-4" />
                {t("transports.add")}
              </Button>
            </span>
          }
          description={t("transports.empty")}
          title={t("transports.emptyTitle")}
        />
      ) : null}

      {query.isLoading || ndmsInventoryQuery.isLoading ? (
        <TableSkeleton />
      ) : null}

      <NativeRouteOffer
        candidates={routeOfferCandidates}
        disabled={routeOfferMutation.isPending || !keenConfig}
        onCreate={createRouteFromOffer}
        onDismiss={dismissRouteOffer}
      />

      {transportTabs.length > 1 ? (
        <SectionTabs
          ariaLabel={t("transports.tabs.ariaLabel")}
          onValueChange={setActiveTransportTab}
          tabs={transportTabs}
          value={activeTransportTab}
        />
      ) : null}
      {/* Слева, а не справа: прижатая вправо кнопка висела в пустой строке и
          отодвигала первую карточку вниз ни за чем. Отрицательный отступ
          сверху убирает лишний ритм над ней; снизу его быть не должно —
          кнопка наезжала на первую карточку. */}
      {hiddenNativeCount > 0 ? (
        <div className="-mt-1 flex justify-start">
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

      {transportRows.length > 0 ? (
        <DataTable
          // Строка прошивки — ровно 48px. Обычная ячейка укладывается в них с
          // отступом 12px: содержимое там не выше 24px. В колонках управления
          // стоят кнопки в 32px, и те же 12px растягивали строку до 56px —
          // поэтому у них отступ 8px, и ряд снова 48px.
          columnClassNames={[
            "py-2",
            // Колонка имени забирает весь остаток ширины и сжимается первой,
            // когда его не хватает. `w-full` — «этой колонке отдать остаток»,
            // `max-width: 0` — «не требовать ширину по самому длинному имени»:
            // без второго ячейка распирала таблицу, и вместо многоточия
            // появлялась горизонтальная прокрутка. Только на ячейках: то же
            // правило на заголовке схлопывает колонку до слова «Название».
            "w-full [&:where(td)]:max-w-0",
            // Состояние и задержка — колонки фиксированной ширины. Задержка
            // приезжает каждые три секунды, и «38 мс · 6 с назад» превращалось
            // в «112 мс · 12 с назад»: колонка становилась шире, и вся таблица
            // дёргалась сама по себе. Ширина взята по самому длинному
            // содержимому («Есть проблема», «1234 мс · 999 с назад»), поэтому
            // расти ей больше не с чего.
            "min-w-[11rem]",
            "min-w-[11rem]",
            // «Где используется» переносится, а не расталкивает соседей: с
            // плашками зависимостей узкая nowrap-колонка вырастала до своего
            // max-content (~360px) и сжимала имя туннеля до одной буквы.
            // Тот же приём, что у имени: `max-width: 0` на ячейке — «не
            // требовать ширину по содержимому», пол в 14rem — чтобы плашки
            // не рассыпались по слову на строку.
            "min-w-[14rem] [&:where(td)]:max-w-0",
            "py-2",
          ]}
          groupHeadings={
            Object.keys(transportGroupHeadings).length > 0
              ? transportGroupHeadings
              : undefined
          }
          headers={transportTableHeaders}
          // Колонки состояния и задержки — постоянной ширины, имя забирает
          // остаток. Только так таблица не шевелится: данные в ней обновляются
          // каждые три секунды. «Где используется» не в списке: ей нужен
          // перенос строк, nowrap раздувал её до самой длинной плашки.
          narrowColumns={[0, 2, 3]}
          rowDetails={transportRowDetails}
          rows={transportRows.map((row) => row.cells)}
        />
      ) : null}

      {processModeQuery.data ? (
        <SingBoxProcessModeDialog
          currentMode={processModeQuery.data.sing_box_process_mode}
          onModeChange={setSelectedProcessMode}
          onOpenChange={setProcessModeDialogOpen}
          onSubmit={() => processModeMutation.mutate(selectedProcessMode)}
          open={processModeDialogOpen}
          pending={processModeMutation.isPending}
          restartRequired={processModeQuery.data.restart_required}
          selectedMode={selectedProcessMode}
        />
      ) : null}
      <DeleteImpactDialog
        confirmLabel={t("common.delete")}
        description={
          deletingLinkedOutbound
            ? t("transports.deleteWithRouteDescription")
            : t("transports.deleteDescription")
        }
        impactItems={
          deleting
            ? deletingLinkedOutbound && keenConfig
              ? getOutboundDeleteImpactItems(
                  keenConfig,
                  [deletingLinkedOutbound.tag],
                  getOutboundDeleteImpact(keenConfig, [
                    deletingLinkedOutbound.tag,
                  ]),
                  t
                )
              : [{ label: deleting.tag }]
            : []
        }
        isPending={configMutation.isPending || routeDeleteMutation.isPending}
        onConfirm={() => {
          if (!deleting) {
            return
          }

          const deleteTransport = () =>
            configMutation.mutate(
              {
                data: {
                  operation: TransportConfigOperationOperation.delete,
                  tag: deleting.tag,
                },
              },
              deletingLinkedOutbound
                ? {
                    onSuccess: () => {
                      toast.info(t("transports.routeStagedForDelete"))
                    },
                    onError: () => {
                      // Маршрут уже в черновике на удаление, а туннель остался.
                      // Молчать нельзя: состояния разъехались, и человек должен
                      // знать, что повторить.
                      toast.error(
                        t("transports.deleteTunnelAfterRouteFailed"),
                        { richColors: true }
                      )
                    },
                  }
                : undefined
            )

          if (deletingLinkedOutbound && keenConfig) {
            routeDeleteMutation.mutate(
              {
                data: buildUpdatedConfigForOutboundsDelete(keenConfig, [
                  deletingLinkedOutbound.tag,
                ]),
              },
              { onSuccess: deleteTransport }
            )
            return
          }

          deleteTransport()
        }}
        onOpenChange={(open) => !open && setDeleting(undefined)}
        open={Boolean(deleting)}
        title={t("transports.deleteTitle")}
      />
    </div>
  )
}

/**
 * Имя туннеля в строке таблицы: тип, страна, название, транспорт.
 *
 * Всё в одну строку — иначе запись занимает две и ряд перестаёт быть 48px, как
 * в прошивке. Порядок оставлен прежним: сначала «что это» (VLESS, AWG), потом
 * «где» (флаг), потом название, и в конце — «как идёт по проводу». Техническое
 * имя интерфейса сюда не входит: оно выдано ядром и живёт в подробностях.
 */
function TransportName({
  name,
  protocol,
  location,
  wire,
  technicalTag,
}: {
  readonly name: string
  readonly protocol: string
  readonly location?: ServerLocation
  /** «UDP · QUIC», «TCP · Reality» — чем этот туннель отличается от соседнего. */
  readonly wire?: string | null
  readonly technicalTag?: string
}) {
  const flag = countryMark(location)

  return (
    // Перенос только на телефоне: там это заголовок карточки во всю ширину, и
    // пилюля транспорта может уехать на вторую строку, лишь бы имя осталось
    // читаемым. В таблице переносить нельзя — строка перестанет быть 48px.
    <span className="flex min-w-0 items-center gap-x-2 gap-y-1 max-sm:flex-wrap">
      <TransportProtocolIcon protocol={protocol} />
      {flag ? (
        <span
          aria-label={location?.country ?? location?.country_code ?? ""}
          className="shrink-0 text-base leading-none"
          role="img"
          title={location?.country ?? location?.country_code ?? ""}
        >
          {flag}
        </span>
      ) : null}
      <span
        className="truncate max-sm:min-w-[8rem]"
        title={technicalTag ?? name}
      >
        {name}
      </span>
      {wire ? (
        <Badge
          className="shrink-0 font-mono text-[10px]"
          size="xs"
          variant="outline"
        >
          {wire}
        </Badge>
      ) : null}
    </span>
  )
}

/**
 * Срезать у плашки правила хвост «→ сам туннель». Плашка правила говорит
 * «правило → куда»; рядом со строкой этого самого туннеля хвост повторяет её
 * имя — по новой концепции маршрут не показывается. selfNames — отображаемое
 * имя и тег.
 */
function trimSelfRouteSuffix(
  dependencies: readonly Dependency[] | undefined,
  selfNames: readonly string[]
): Dependency[] {
  const suffixes = selfNames
    .filter((name) => name.length > 0)
    .map((name) => ` → ${name}`)
  return [...(dependencies ?? [])].map((dependency) => {
    if (dependency.kind !== "routingRule") return dependency
    const suffix = suffixes.find((entry) => dependency.label.endsWith(entry))
    return suffix
      ? { ...dependency, label: dependency.label.slice(0, -suffix.length) }
      : dependency
  })
}

/**
 * Порядок категорий в раскрытой строке туннеля — решение владельца: правила,
 * DNS-серверы, списки, группы. Все четыре видны всегда, пустые — с «-».
 */
const TUNNEL_USAGE_KINDS = [
  "routingRule",
  "dnsServer",
  "list",
  "failoverGroup",
] as const

/** «Где используется» — тот же вопрос «можно ли это удалить», что и в маршрутах. */
function UsedByCell({
  bound,
  dependencies,
  selfNames = [],
}: {
  /** Есть ли у туннеля маршрут вообще. Без маршрута использовать его нечем. */
  readonly bound: boolean
  readonly dependencies?: readonly Dependency[]
  /** Имена самого туннеля (отображаемое и тег) — для среза хвоста плашки. */
  readonly selfNames?: readonly string[]
}) {
  const { t } = useTranslation()

  // Тег маршрута здесь больше не показывается: туннель и есть маршрут, и имя
  // маршрута повторяло имя туннеля из соседней колонки. Вместо этого — кто
  // туннелем пользуется, но не больше двух строк (решение владельца: строки
  // таблицы одной высоты, полный список — в раскрытии строки). min-h — чтобы
  // строка с одной категорией была той же высоты, что с двумя.
  return (
    <DependencyList
      cellRows={2}
      className="min-h-[46px]"
      dependencies={bound ? trimSelfRouteSuffix(dependencies, selfNames) : []}
      emptyHint={bound ? undefined : t("transports.usedByNone")}
    />
  )
}

/**
 * Карандаш, корзинка и раскрытие в конце строки.
 *
 * Карандаш с корзинкой появляются по наведению — так это сделано в таблицах
 * KeeneticOS (`.ndw-table__row-group:hover .ndw-table__cell-pencil`). Прозрачность,
 * а не `visibility`: скрытая кнопка выпадает из обхода по Tab, и до удаления
 * нельзя было бы добраться с клавиатуры. Там, где наведения не бывает
 * (сенсорный экран), кнопки видны всегда.
 */
function RowActions({
  expanded,
  toggleTitle,
  onToggleExpanded,
  onEdit,
  onDelete,
  editDisabled,
  deleteDisabled,
  editTitle,
  deleteTitle,
}: {
  readonly expanded: boolean
  readonly toggleTitle: string
  readonly onToggleExpanded: () => void
  readonly onEdit: () => void
  readonly onDelete: () => void
  readonly editDisabled?: boolean
  readonly deleteDisabled?: boolean
  readonly editTitle: string
  readonly deleteTitle: string
}) {
  return (
    <span className="flex items-center justify-end gap-1">
      {/* Появление и вид — общие с таблицами правил и списков: класс
          `keen-row-actions` прячет группу до наведения там, где курсор есть,
          `keen-row-action` даёт прошивочную кнопку 32×32 с рамкой. Раньше тут
          было своё скрытие через прозрачность и кнопки без рамки — из-за
          этого одни и те же действия на разных страницах выглядели по-разному. */}
      <span className="keen-row-actions flex items-center gap-1">
        <Button
          aria-label={editTitle}
          className="keen-row-action size-8 rounded-[4px]"
          disabled={editDisabled}
          onClick={onEdit}
          size="icon"
          title={editTitle}
          variant="outline"
        >
          <KeenPencilIcon className="size-4" />
        </Button>
        <Button
          aria-label={deleteTitle}
          className={cn(
            "keen-row-action size-8 rounded-[4px]",
            !deleteDisabled && "keen-row-action--danger"
          )}
          disabled={deleteDisabled}
          onClick={onDelete}
          size="icon"
          title={deleteTitle}
          variant="outline"
        >
          <KeenTrashIcon className="size-4" />
        </Button>
      </span>
      <Button
        aria-expanded={expanded}
        aria-label={toggleTitle}
        className="size-8"
        onClick={onToggleExpanded}
        size="icon"
        title={toggleTitle}
        variant="ghost"
      >
        <ChevronDownIcon
          className={cn(
            "size-4 transition-transform",
            expanded && "rotate-180"
          )}
        />
      </Button>
    </span>
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
    // Подпись в колонке фиксированной ширины, значение сразу за ней и по левому
    // краю. В карточке значение прижималось вправо и это читалось — там строка
    // была узкая. Под таблицей во всю ширину между подписью и значением
    // оставалось полэкрана пустоты, и глазу приходилось их сводить.
    <div className="grid min-w-0 grid-cols-[minmax(0,9rem)_minmax(0,1fr)] items-baseline gap-3">
      <span className="min-w-0 truncate text-muted-foreground" title={label}>
        {label}
      </span>
      <span className="min-w-0 truncate font-mono" title={value}>
        {value}
      </span>
    </div>
  )
}

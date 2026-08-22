import { useQuery, useQueryClient } from "@tanstack/react-query"
import { useState } from "react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"
import { useLocation } from "wouter"

import type { ApiError } from "@/api/client"
import { postConfigSave, postTransportConfig } from "@/api/generated/keen-api"
import {
  TransportConfigOperationOperation,
  TransportSpecType,
  type TransportSpec,
  type TransportStatus,
} from "@/api/generated/model"
import {
  createLinkedTransportApplyRequest,
  usePostConfigMutation,
  usePostTransportConfigApplyMutation,
  usePostTransportConfigMutation,
} from "@/api/mutations"
import {
  useGetConfig,
  useGetNdmsInterfaceInventory,
  useGetRuntimeInterfaces,
  useGetTransportConfig,
  useGetTransports,
} from "@/api/queries"
import { selectConfig } from "@/api/selectors"
import {
  UpsertPage,
  type UpsertPagePresentation,
} from "@/components/shared/upsert-page"
import {
  TransportConfigForm,
  type TransportKillSwitchOption,
} from "@/components/transports/transport-config-dialog"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { getApiErrorMessage } from "@/lib/api-errors"
import { buildNativeTransportCandidates } from "@/lib/hidden-native-interfaces"
import { mapNativeInterfaces } from "@/lib/native-interfaces"
import { makeTechnicalId } from "@/lib/technical-id"
import { readNativeTransportCreateInterface } from "@/lib/transport-upsert-route"
import {
  clearStagedNativeWireGuardImportCompletion,
  readStagedNativeWireGuardImportCompletion,
} from "@/lib/native-wireguard-import-completion"
import { resolveNativeWireGuardImportLocation } from "@/lib/native-wireguard-import-geo"
import { queryKeys } from "@/api/query-keys"

type TransportEnvironment = {
  sing_box_installed: boolean
  sing_box_binary: string
  tested_version: string
  transport_api_version?: number
}

export function TransportUpsertPage({
  mode,
  presentation = "page",
  transportTag,
}: {
  mode: "create" | "edit"
  presentation?: UpsertPagePresentation
  transportTag?: string
}) {
  const { t } = useTranslation()
  const [, navigate] = useLocation()
  const queryClient = useQueryClient()
  const [dirty, setDirty] = useState(false)
  const [linkedRouteApplyPending, setLinkedRouteApplyPending] = useState(false)
  const configQuery = useGetTransportConfig()
  const transportsQuery = useGetTransports()
  const keenConfigQuery = useGetConfig()
  const ndmsInventoryQuery = useGetNdmsInterfaceInventory()
  const runtimeInterfacesQuery = useGetRuntimeInterfaces()
  const environmentQuery = useQuery({
    queryKey: ["transport-environment"],
    queryFn: async () => {
      const response = await fetch("/api/transports/environment")
      if (!response.ok) throw new Error("transport environment unavailable")
      return (await response.json()) as TransportEnvironment
    },
  })
  const configured: TransportSpec[] =
    configQuery.data?.status === 200 ? configQuery.data.data : []
  const runtimeTransports: TransportStatus[] =
    transportsQuery.data?.status === 200 ? transportsQuery.data.data : []
  const loadedConfig = selectConfig(keenConfigQuery.data)
  const initial =
    mode === "edit"
      ? configured.find((transport) => transport.tag === transportTag)
      : undefined
  const loading =
    configQuery.isLoading ||
    transportsQuery.isLoading ||
    keenConfigQuery.isLoading ||
    ndmsInventoryQuery.isLoading ||
    runtimeInterfacesQuery.isLoading ||
    environmentQuery.isLoading
  const loadFailed =
    configQuery.isError ||
    keenConfigQuery.isError ||
    environmentQuery.isError ||
    (!loading &&
      (configQuery.data?.status !== 200 || loadedConfig === undefined))
  const nativeInterfaces = mapNativeInterfaces(
    ndmsInventoryQuery.data?.status === 200 &&
      ndmsInventoryQuery.data.data.available
      ? ndmsInventoryQuery.data.data.interfaces
      : [],
    runtimeInterfacesQuery.data?.status === 200
      ? runtimeInterfacesQuery.data.data.interfaces
      : []
  )
  const nativeCandidates = buildNativeTransportCandidates(
    nativeInterfaces,
    loadedConfig
  )
  const requestedNativeInterface =
    mode === "create"
      ? readNativeTransportCreateInterface(window.location.search)
      : undefined

  const finishNativeImport = (transport: TransportSpec) => {
    if (transport.type !== TransportSpecType.native) return
    const plan = readStagedNativeWireGuardImportCompletion()
    if (!plan || plan.tag !== transport.tag) return
    if (plan.geoMode !== "auto" || !plan.endpointHost) {
      clearStagedNativeWireGuardImportCompletion(plan.tag)
      return
    }

    void resolveNativeWireGuardImportLocation(plan.endpointHost)
      .then(async (location) => {
        if (!location) return
        const response = await postTransportConfig({
          operation: TransportConfigOperationOperation.update,
          tag: transport.tag,
          transport: {
            ...transport,
            country_code: location.country_code,
            country: location.country,
          },
        })
        if (response.status !== 200) return
        await Promise.all([
          queryClient.invalidateQueries({
            queryKey: queryKeys.transportConfig(),
          }),
          queryClient.invalidateQueries({ queryKey: queryKeys.transports() }),
        ])
      })
      .catch(() => undefined)
      .finally(() => clearStagedNativeWireGuardImportCompletion(plan.tag))
  }
  const configMutation = usePostTransportConfigMutation({
    mutation: {
      onSuccess: (_data, variables) => {
        const isNativeTracker =
          variables.data.transport?.type === TransportSpecType.native
        if (variables.data.transport) {
          finishNativeImport(variables.data.transport)
        }
        toast.success(
          isNativeTracker
            ? t(
                variables.data.operation ===
                  TransportConfigOperationOperation.create
                  ? "transports.configMessages.nativeLinked"
                  : "transports.configMessages.nativeTrackerUpdated"
              )
            : t(`transports.configMessages.${variables.data.operation}`)
        )
        navigate("/transports")
      },
      onError: (mutationError) => {
        toast.error(getApiErrorMessage(mutationError as ApiError), {
          richColors: true,
        })
      },
    },
  })
  const configApplyMutation = usePostTransportConfigApplyMutation()
  // Изменение kill-switch живёт в связанном маршруте, то есть в черновике
  // конфигурации, — отдельная мутация с отдельным сообщением об ошибке.
  const routeMutation = usePostConfigMutation()
  const close = () => navigate("/transports")
  const editsNativeTracker =
    (mode === "edit" && initial?.type === TransportSpecType.native) ||
    Boolean(requestedNativeInterface)
  const title =
    mode === "create"
      ? t("transports.form.createTitle")
      : editsNativeTracker
        ? t("transports.form.editNativeTrackerTitle")
        : t("transports.form.editTitle")
  const description = editsNativeTracker
    ? t("transports.form.editNativeTrackerDescription")
    : t("transports.form.description")

  if (loadFailed) {
    return (
      <UpsertPage
        cardDescription={t("transports.form.loadErrorDescription")}
        cardTitle={t("transports.form.loadErrorTitle")}
        description={description}
        onClose={close}
        presentation={presentation}
        title={title}
      >
        <Alert variant="destructive">
          <AlertTitle>{t("transports.form.loadErrorTitle")}</AlertTitle>
          <AlertDescription>
            {t("transports.form.loadErrorDescription")}
          </AlertDescription>
        </Alert>
        <div className="mt-4 flex justify-end gap-3" data-upsert-actions>
          <Button onClick={close} size="xl" type="button" variant="outline">
            {t("transports.form.back")}
          </Button>
          <Button
            onClick={() => {
              void Promise.all([
                configQuery.refetch(),
                keenConfigQuery.refetch(),
                environmentQuery.refetch(),
              ])
            }}
            size="xl"
            type="button"
          >
            {t("common.retry")}
          </Button>
        </div>
      </UpsertPage>
    )
  }

  if (loading || !loadedConfig) {
    return (
      <UpsertPage
        cardDescription={description}
        cardTitle={title}
        description={description}
        onClose={close}
        presentation={presentation}
        title={title}
      >
        <div className="space-y-3">
          <div className="h-8 rounded-lg bg-muted" />
          <div className="h-24 rounded-lg bg-muted" />
          <div className="h-8 rounded-lg bg-muted" />
        </div>
      </UpsertPage>
    )
  }

  if (mode === "edit" && !initial) {
    return (
      <UpsertPage
        cardDescription={t("transports.form.missingDescription")}
        cardTitle={t("transports.form.missingTitle")}
        description={t("transports.form.missingDescription")}
        onClose={close}
        presentation={presentation}
        title={title}
      >
        <div className="flex justify-end" data-upsert-actions>
          <Button onClick={close} size="xl" variant="outline">
            {t("transports.form.back")}
          </Button>
        </div>
      </UpsertPage>
    )
  }

  const existingInterfaces = [
    ...configured.map((spec) => spec.interface),
    ...runtimeTransports.map((transport) => transport.interface),
    ...(loadedConfig.outbounds ?? []).flatMap((outbound) =>
      typeof outbound.interface === "string" ? [outbound.interface] : []
    ),
  ]
  const existingTags = [
    ...configured.map((spec) => spec.tag),
    ...runtimeTransports.map((transport) => transport.tag),
    ...(loadedConfig.outbounds ?? []).map((outbound) => outbound.tag),
  ]

  const nativeCreateCandidate = requestedNativeInterface
    ? nativeCandidates.find(
        (candidate) =>
          candidate.selectable &&
          candidate.interfaceName === requestedNativeInterface
      )
    : undefined
  const nativeSeedLinkedOutbound = nativeCreateCandidate
    ? (loadedConfig.outbounds ?? []).find(
        (outbound) =>
          outbound.type === "interface" &&
          outbound.interface === nativeCreateCandidate.interfaceName
      )
    : undefined
  const nativeCreateSeed: TransportSpec | undefined = nativeCreateCandidate
    ? {
        tag: makeTechnicalId(
          nativeSeedLinkedOutbound?.display_name?.trim() ||
            nativeCreateCandidate.label,
          existingTags,
          { prefix: "native" }
        ),
        type: TransportSpecType.native,
        interface: nativeCreateCandidate.interfaceName!,
        display_name:
          nativeSeedLinkedOutbound?.display_name?.trim() ||
          nativeCreateCandidate.label,
        auto_start: false,
        geo_mode: "disabled",
      }
    : undefined

  // Маршрут этого туннеля: по интерфейсу либо по тегу — так же, как строит
  // привязку таблица туннелей.
  const editedInterface = initial?.interface ?? nativeCreateSeed?.interface
  const linkedOutbound = editedInterface
    ? ((loadedConfig.outbounds ?? []).find(
        (outbound) =>
          outbound.type === "interface" &&
          outbound.interface === editedInterface
      ) ??
      (initial
        ? (loadedConfig.outbounds ?? []).find(
            (outbound) =>
              outbound.type === "interface" && outbound.tag === initial.tag
          )
        : undefined))
    : undefined
  const initialKillSwitch: TransportKillSwitchOption =
    linkedOutbound?.strict_enforcement === undefined
      ? "default"
      : linkedOutbound.strict_enforcement
        ? "enabled"
        : "disabled"

  const saveTransport = (
    spec: TransportSpec,
    options: { createOutbound: boolean; killSwitch: TransportKillSwitchOption }
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

    const killSwitchValue =
      options.killSwitch === "default"
        ? undefined
        : options.killSwitch === "enabled"

    if (mode === "create" && options.createOutbound) {
      configApplyMutation.mutate(
        { data: createLinkedTransportApplyRequest(spec, killSwitchValue) },
        {
          onSuccess: () => {
            finishNativeImport(spec)
            toast.success(
              t(
                spec.type === TransportSpecType.native
                  ? "transports.configMessages.nativeLinked"
                  : "transports.configMessages.create"
              )
            )
            navigate("/transports")
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

    const updateTransport = () =>
      configMutation.mutate({
        data:
          mode === "edit" && initial
            ? {
                operation: TransportConfigOperationOperation.update,
                tag: initial.tag,
                transport: spec,
              }
            : {
                operation: TransportConfigOperationOperation.create,
                transport: spec,
              },
      })

    const normalizedDisplayName = spec.display_name?.trim() || undefined
    const strictEnforcement =
      options.killSwitch === "default"
        ? undefined
        : options.killSwitch === "enabled"
    const routeDisplayNameChanged =
      linkedOutbound?.display_name?.trim() !== normalizedDisplayName
    const linkedRouteNeedsUpdate =
      Boolean(linkedOutbound) &&
      (routeDisplayNameChanged || options.killSwitch !== initialKillSwitch)
    const linkedRouteNeedsCreation = !linkedOutbound && options.createOutbound

    if (linkedRouteNeedsCreation || linkedRouteNeedsUpdate) {
      const nextOutbounds = linkedRouteNeedsCreation
        ? [
            ...(loadedConfig.outbounds ?? []),
            {
              type: "interface" as const,
              tag: makeTechnicalId(
                normalizedDisplayName || spec.tag,
                (loadedConfig.outbounds ?? []).map((outbound) => outbound.tag),
                { prefix: "outbound" }
              ),
              display_name: normalizedDisplayName,
              interface: spec.interface,
              strict_enforcement: strictEnforcement,
            },
          ]
        : (loadedConfig.outbounds ?? []).map((outbound) =>
            outbound.tag === linkedOutbound?.tag
              ? {
                  ...outbound,
                  display_name: normalizedDisplayName,
                  strict_enforcement: strictEnforcement,
                }
              : outbound
          )

      routeMutation.mutate(
        {
          data: {
            ...loadedConfig,
            outbounds: nextOutbounds,
          },
        },
        {
          onSuccess: async () => {
            setLinkedRouteApplyPending(true)
            try {
              const applied = await postConfigSave()
              if (applied.status !== 200) {
                throw new Error(applied.data.error)
              }
              updateTransport()
            } catch (mutationError) {
              toast.error(getApiErrorMessage(mutationError as ApiError), {
                richColors: true,
              })
            } finally {
              setLinkedRouteApplyPending(false)
            }
          },
          onError: (mutationError) => {
            toast.error(getApiErrorMessage(mutationError as ApiError), {
              richColors: true,
            })
          },
        }
      )
      return
    }

    updateTransport()
  }

  return (
    <UpsertPage
      cardDescription={description}
      cardTitle={
        initial?.display_name?.trim() ||
        nativeCreateSeed?.display_name?.trim() ||
        initial?.tag ||
        t("transports.form.createTitle")
      }
      description={description}
      dirty={dirty}
      onClose={close}
      presentation={presentation}
      title={title}
    >
      <TransportConfigForm
        createSeed={nativeCreateSeed}
        existingInterfaces={existingInterfaces}
        existingTags={existingTags}
        initial={initial}
        initialCreateOutbound={!linkedOutbound}
        initialKillSwitch={initialKillSwitch}
        isPending={
          configMutation.isPending ||
          configApplyMutation.isPending ||
          routeMutation.isPending ||
          linkedRouteApplyPending
        }
        key={`${mode}:${transportTag ?? nativeCreateSeed?.interface ?? "new"}`}
        killSwitchAvailable={
          mode === "create" || Boolean(initial) || Boolean(linkedOutbound)
        }
        linkedOutboundExists={Boolean(linkedOutbound)}
        nativeCandidates={nativeCandidates}
        nativeImportInterfaces={
          ndmsInventoryQuery.data?.status === 200
            ? ndmsInventoryQuery.data.data.interfaces
            : []
        }
        nativeImportReadiness={
          ndmsInventoryQuery.data?.status === 200
            ? ndmsInventoryQuery.data.data.native_import_readiness
            : undefined
        }
        nativeImportRequiredGuards={
          ndmsInventoryQuery.data?.status === 200
            ? ndmsInventoryQuery.data.data.required_guards
            : []
        }
        onDirtyChange={setDirty}
        onSubmit={saveTransport}
        presentation={presentation}
        singBoxAvailable={environmentQuery.data?.sing_box_installed !== false}
      />
    </UpsertPage>
  )
}

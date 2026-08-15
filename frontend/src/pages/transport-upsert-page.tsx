import { useQuery } from "@tanstack/react-query"
import { useState } from "react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"
import { useLocation } from "wouter"

import type { ApiError } from "@/api/client"
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
  const [dirty, setDirty] = useState(false)
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
  const configMutation = usePostTransportConfigMutation({
    mutation: {
      onSuccess: (_data, variables) => {
        const isNativeTracker =
          variables.data.transport?.type === TransportSpecType.native
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
    mode === "edit" && initial?.type === TransportSpecType.native
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

  // Маршрут этого туннеля: по интерфейсу либо по тегу — так же, как строит
  // привязку таблица туннелей.
  const linkedOutbound = initial
    ? ((loadedConfig.outbounds ?? []).find(
        (outbound) =>
          outbound.type === "interface" &&
          outbound.interface === initial.interface
      ) ??
      (loadedConfig.outbounds ?? []).find(
        (outbound) =>
          outbound.type === "interface" && outbound.tag === initial.tag
      ))
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

    // Kill-switch изменился — сначала изменение маршрута уходит в черновик
    // (до «Применить» на роутере ничего не меняется), потом обновляется сам
    // туннель. Тот же порядок, что при удалении: упади второй шаг, черновик
    // останется виден и его можно применить или отменить, а не потеряться.
    if (
      mode === "edit" &&
      linkedOutbound &&
      options.killSwitch !== initialKillSwitch
    ) {
      routeMutation.mutate(
        {
          data: {
            ...loadedConfig,
            outbounds: (loadedConfig.outbounds ?? []).map((outbound) =>
              outbound.tag === linkedOutbound.tag
                ? { ...outbound, strict_enforcement: killSwitchValue }
                : outbound
            ),
          },
        },
        {
          onSuccess: () => {
            toast.success(t("transports.killSwitchStaged"))
            updateTransport()
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

  return (
    <UpsertPage
      cardDescription={description}
      cardTitle={
        initial?.display_name?.trim() ||
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
        existingInterfaces={existingInterfaces}
        existingTags={existingTags}
        initial={initial}
        initialKillSwitch={initialKillSwitch}
        isPending={
          configMutation.isPending ||
          configApplyMutation.isPending ||
          routeMutation.isPending
        }
        key={`${mode}:${transportTag ?? "new"}`}
        killSwitchAvailable={mode === "create" || Boolean(linkedOutbound)}
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

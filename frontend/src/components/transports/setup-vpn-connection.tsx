import { useQuery, useQueryClient } from "@tanstack/react-query"
import { useEffect, useRef, useState } from "react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"

import type {
  Outbound,
  TransportSpec,
  TransportsEnvironment,
} from "@/api/generated/model"
import {
  createLinkedTransportApplyRequest,
  usePostTransportConfigApplyMutation,
} from "@/api/mutations"
import {
  useGetConfig,
  useGetNdmsInterfaceInventory,
  useGetTransportConfig,
} from "@/api/queries"
import { queryKeys } from "@/api/query-keys"
import { selectConfig } from "@/api/selectors"
import { OperationErrorMessage } from "@/components/shared/operation-error-message"
import { UpsertCloseContext } from "@/components/shared/upsert-page-context"
import { NativeMutationRecovery } from "@/components/transports/native-mutation-recovery"
import { SingBoxSetupOffer } from "@/components/transports/sing-box-setup-offer"
import { TransportConfigForm } from "@/components/transports/transport-config-dialog"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import {
  buildStagedNativeWireGuardTransport,
  clearStagedNativeWireGuardImportCompletion,
  findStagedNativeWireGuardImportIdentity,
  NATIVE_WIREGUARD_IMPORT_PROGRESS_TOAST_ID,
  offerNativeWireGuardImportCompletion,
  readStagedNativeWireGuardImportCompletion,
  rememberNativeWireGuardImportedIdentity,
  stagedNativeWireGuardLinkState,
  type NativeWireGuardImportedIdentity,
} from "@/lib/native-wireguard-import-completion"
import { persistNativeWireGuardImportCountry } from "@/lib/native-wireguard-import-country"
import {
  readNativeMutationLock,
  subscribeNativeMutationLock,
} from "@/lib/native-mutation-lock"

/** The wizard is another host for the normal importer, not another parser. */
export function SetupVpnConnection({
  configured,
  outbounds,
  onCreated,
  onBusyChange,
}: {
  configured: readonly TransportSpec[]
  outbounds: readonly Outbound[]
  onCreated: (tag: string, name: string) => void
  onBusyChange: (busy: boolean) => void
}) {
  const { t } = useTranslation()
  const client = useQueryClient()
  const configQuery = useGetConfig()
  const transportsQuery = useGetTransportConfig()
  const inventoryQuery = useGetNdmsInterfaceInventory()
  const environmentQuery = useQuery({
    queryKey: ["transport-environment"],
    queryFn: async (): Promise<TransportsEnvironment> => {
      const response = await fetch("/api/transports/environment")
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      return response.json()
    },
  })
  const inventory =
    inventoryQuery.data?.status === 200 ? inventoryQuery.data.data : undefined
  const applyMutation = usePostTransportConfigApplyMutation()
  const saving = useRef(false)
  const [handedOff, setHandedOff] = useState(() =>
    Boolean(readStagedNativeWireGuardImportCompletion())
  )
  const [lock, setLock] = useState(readNativeMutationLock)
  const [completionPaused, setCompletionPaused] = useState(false)
  const [retryingCompletion, setRetryingCompletion] = useState(false)
  const [dirty, setDirty] = useState(false)
  const [formKey, setFormKey] = useState(0)
  useEffect(() => subscribeNativeMutationLock(setLock), [])
  const busy =
    retryingCompletion ||
    applyMutation.isPending ||
    (lock?.state === "pending" &&
      (lock.operation === "import" || lock.operation === "import_recovery"))
  useEffect(() => {
    onBusyChange(busy)
    return () => onBusyChange(false)
  }, [busy, onBusyChange])

  const finish = (transport: TransportSpec) => {
    const plan = readStagedNativeWireGuardImportCompletion()
    if (plan?.tag === transport.tag) {
      // Country is optional metadata: a failed lookup must not lose a VPN.
      if (plan.endpointHost && transport.geo_mode === "auto") {
        void persistNativeWireGuardImportCountry(transport, plan.endpointHost)
          .then(() =>
            client.invalidateQueries({ queryKey: queryKeys.transportConfig() })
          )
          .catch(() => undefined)
      }
      clearStagedNativeWireGuardImportCompletion(plan.tag)
    }
    toast.success(t("transports.nativeImport.importedToast"), {
      id: NATIVE_WIREGUARD_IMPORT_PROGRESS_TOAST_ID,
    })
    onCreated(transport.tag, transport.display_name ?? transport.tag)
  }

  const save = async (transport: TransportSpec): Promise<boolean> => {
    if (saving.current) return false
    if (
      transport.type !== "native" &&
      environmentQuery.data?.sing_box_installed !== true
    )
      return false
    saving.current = true
    try {
      // Always one server transaction: no tracker without its selectable route.
      await applyMutation.mutateAsync({
        data: createLinkedTransportApplyRequest(transport),
      })
      finish(transport)
      return true
    } catch (error) {
      toast.error(<OperationErrorMessage error={error} />, {
        id: NATIVE_WIREGUARD_IMPORT_PROGRESS_TOAST_ID,
      })
      return false
    } finally {
      saving.current = false
    }
  }

  const completeIdentity = async (
    identity: NativeWireGuardImportedIdentity
  ): Promise<boolean | undefined> => {
    rememberNativeWireGuardImportedIdentity(identity)
    if (offerNativeWireGuardImportCompletion(identity)) return true
    const plan = readStagedNativeWireGuardImportCompletion()
    if (!plan) return false
    const [transports, config] = await Promise.all([
      transportsQuery.refetch(),
      configQuery.refetch(),
    ])
    const active = selectConfig(config.data)
    if (
      transports.isError ||
      config.isError ||
      transports.data?.status !== 200 ||
      config.data?.status !== 200 ||
      config.data.data.is_draft ||
      !active
    )
      return undefined
    const transport = buildStagedNativeWireGuardTransport(plan, identity)
    const state = stagedNativeWireGuardLinkState(
      plan,
      identity,
      transports.data.data,
      active.outbounds ?? []
    )
    if (state === "conflict") {
      toast.error(t("transports.nativeImport.panelLinkCreationFailed"), {
        id: NATIVE_WIREGUARD_IMPORT_PROGRESS_TOAST_ID,
      })
      return false
    }
    if (state === "complete") {
      finish(transport)
      return true
    }
    return save(transport)
  }

  const reconnect = async (): Promise<boolean | undefined> => {
    const plan = readStagedNativeWireGuardImportCompletion()
    if (!plan) return false
    const [inventoryResult, transports] = await Promise.all([
      inventoryQuery.refetch(),
      transportsQuery.refetch(),
    ])
    if (
      inventoryResult.isError ||
      transports.isError ||
      inventoryResult.data?.status !== 200 ||
      !inventoryResult.data.data.available ||
      transports.data?.status !== 200
    )
      return undefined
    const identity = findStagedNativeWireGuardImportIdentity(
      plan,
      inventoryResult.data.data.interfaces,
      transports.data.data
        .filter((item) => item.type === "native" && item.tag !== plan.tag)
        .map((item) => item.interface)
    )
    return identity ? completeIdentity(identity) : undefined
  }

  const refresh = async () => {
    await Promise.all([
      inventoryQuery.refetch(),
      configQuery.refetch(),
      transportsQuery.refetch(),
    ])
  }
  const retryCompletion = async () => {
    if (busy) return
    setRetryingCompletion(true)
    try {
      const completed = await reconnect().catch(() => undefined)
      setCompletionPaused(completed !== true)
    } finally {
      setRetryingCompletion(false)
    }
  }
  const handOff = () => {
    if (readStagedNativeWireGuardImportCompletion()) setHandedOff(true)
    else {
      // Subscription imports may create several routes; let the user choose
      // one in the existing selector instead of guessing their destination.
      void refresh()
      setFormKey((key) => key + 1)
    }
  }
  const names = new Set(configured.map((item) => item.display_name))
  const baseName = t("pages.setupWizard.connection.defaultName")
  let defaultName = baseName
  for (let suffix = 2; names.has(defaultName); suffix++)
    defaultName = `${baseName} ${suffix}`

  return (
    <div className="space-y-4">
      <NativeMutationRecovery
        inventoryStatus={inventory?.native_mutation_status}
        onDeleteTerminal={() => void refresh()}
        onImportCompleted={(result) => {
          if (
            result.status !== "completed" ||
            !result.created_interface ||
            !result.created_kernel_interface ||
            !result.kind
          )
            return
          return completeIdentity({
            firmwareInterface: result.created_interface,
            kernelInterface: result.created_kernel_interface,
            kind: result.kind,
          })
        }}
        onImportNoWork={reconnect}
        onImportCompletionStalled={() => setCompletionPaused(true)}
        onInventoryRefresh={refresh}
      />
      {handedOff ? (
        <div className="space-y-3">
          <p role="status" className="text-sm text-muted-foreground">
            {completionPaused
              ? t("pages.setupWizard.connection.completionPaused")
              : t("pages.setupWizard.connection.finishingImport")}
          </p>
          {completionPaused ? (
            <Button
              type="button"
              variant="outline"
              disabled={busy}
              onClick={() => void retryCompletion()}
            >
              {t("common.retry")}
            </Button>
          ) : null}
        </div>
      ) : environmentQuery.isPending ? (
        <p role="status" className="text-sm text-muted-foreground">
          {t("pages.setupWizard.connection.inventoryLoading")}
        </p>
      ) : environmentQuery.isError ? (
        <Alert>
          <AlertDescription>
            <p>{t("pages.setupWizard.connection.inventoryUnavailable")}</p>
            <Button
              variant="outline"
              onClick={() => void environmentQuery.refetch()}
            >
              {t("common.retry")}
            </Button>
          </AlertDescription>
        </Alert>
      ) : (
        <>
          {!environmentQuery.data.sing_box_installed ? (
            <SingBoxSetupOffer />
          ) : null}
          <UpsertCloseContext.Provider
            value={{ close: () => undefined, complete: handOff }}
          >
            <TransportConfigForm
              key={formKey}
              purpose="setup"
              defaultDisplayName={defaultName}
              existingTags={[
                ...configured.map((item) => item.tag),
                ...outbounds.map((item) => item.tag),
              ]}
              existingInterfaces={[
                ...configured.map((item) => item.interface),
                ...outbounds.flatMap((item) =>
                  item.interface ? [item.interface] : []
                ),
              ]}
              nativeImportInterfaces={inventory?.interfaces}
              nativeImportReadiness={inventory?.native_import_readiness}
              nativeImportRequiredGuards={inventory?.required_guards}
              onDirtyChange={setDirty}
              onSubmit={(transport) => {
                void save(transport)
              }}
              isPending={applyMutation.isPending}
              presentation="dialog"
              singBoxAvailable={environmentQuery.data.sing_box_installed}
            />
          </UpsertCloseContext.Provider>
          {dirty ? (
            <p className="text-xs text-muted-foreground">
              {t("pages.setupWizard.connection.saveHint")}
            </p>
          ) : null}
        </>
      )}
    </div>
  )
}

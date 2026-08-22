import {
  CheckCircle2Icon,
  FileKey2Icon,
  FileUpIcon,
  ShieldAlertIcon,
  XIcon,
} from "lucide-react"
import { useQueryClient } from "@tanstack/react-query"
import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type ChangeEvent,
  type ClipboardEvent,
  type DragEvent,
  type KeyboardEvent,
} from "react"
import { useTranslation } from "react-i18next"

import {
  NativeSecretTransportError,
  postNdmsNativeImportSecretOnce,
  preflightNdmsNativeImport,
} from "@/api/native-secret-transport"
import { queryKeys } from "@/api/query-keys"
import type {
  NdmsInterfaceInventoryResponseRequiredGuardsItem,
  NdmsNativeImportReadiness,
  NdmsTunnelInterface,
} from "@/api/generated/model"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { useTrustedAuthStatus } from "@/lib/auth-status-context"
import {
  NATIVE_WIREGUARD_CONF_MAX_BYTES,
  NATIVE_WIREGUARD_URI_MAX_BYTES,
  classifyNativeWireGuardSensitiveInput,
  createNativeWireGuardFileReadGate,
  normalizeNativeWireGuardSensitiveInput,
  type NativeWireGuardImportFileIssue,
  validateNativeWireGuardImportFile,
  validateNativeWireGuardImportText,
} from "@/lib/native-wireguard-import-file"
import type {
  NativeWireGuardImportErrorCode,
  NativeWireGuardImportPreview,
} from "@/lib/native-wireguard-config-preview"
import {
  findNativeWireGuardAliasConflict,
  suggestNativeWireGuardImportAlias,
} from "@/lib/native-wireguard-import-alias"
import { currentNativeWireGuardImportTransportIsProtected } from "@/lib/native-wireguard-import-transport"
import { nativeWireGuardImportAdmissionRevision } from "@/lib/native-wireguard-import-admission"
import {
  nativeWireGuardImportIntakeIsLocked,
  nativeWireGuardImportOperationSurvivesContextChange,
} from "@/lib/native-wireguard-import-operation"
import {
  readNativeWireGuardImportLock,
  subscribeNativeWireGuardImportLock,
} from "@/lib/native-wireguard-import-lock"
import { runWithNativeMutationLease } from "@/lib/native-mutation-lock"
import {
  ndmsNativeImportOutcome,
  parseNdmsNativeImportResult,
  provedCompletedNativeImportIdentity,
  type NdmsNativeImportClientResult,
  type NdmsNativeImportOutcome,
} from "@/lib/native-wireguard-import-result"
import {
  createNativeWireGuardSecretVault,
  type NativeWireGuardSecretTicket,
  type NativeWireGuardSecretVault,
} from "@/lib/native-wireguard-secret-vault"
import { parseNativeWireGuardInputPreview } from "@/lib/native-wireguard-vpn-uri-preview"
import { looksLikeWireGuardConfig } from "@/components/transports/subscription-import-model"
import { cn } from "@/lib/utils"
import {
  registerActiveNativeWireGuardImportCompletion,
  type NativeWireGuardImportedIdentity,
} from "@/lib/native-wireguard-import-completion"

type ImportState =
  | { readonly status: "empty" }
  | { readonly status: "loading"; readonly fileName: string }
  | {
      readonly status: "error"
      readonly fileName?: string
      readonly code:
        | NativeWireGuardImportFileIssue
        | NativeWireGuardImportErrorCode
        | "secret-buffer-failed"
      readonly line?: number
    }
  | {
      readonly status: "ready"
      readonly fileName: string
      readonly fileSize: number
      readonly aliasSourceFileName?: string
      readonly preview: NativeWireGuardImportPreview
      readonly ticket: NativeWireGuardSecretTicket
    }

type ImportOperationState =
  | { readonly status: "idle" }
  | { readonly status: "preflighting" }
  | { readonly status: "sending" }
  | { readonly status: "preflight-error" }
  | { readonly status: "not-imported" }
  | { readonly status: "selection-expired" }
  | { readonly status: "unknown" }
  | { readonly status: "recovery-locked" }
  | {
      readonly status: "result"
      readonly outcome: NdmsNativeImportOutcome
      readonly result: NdmsNativeImportClientResult
    }

const importWasDefinitelyNotStarted = (
  response: Response,
  payload: unknown
): boolean => {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return false
  }
  const error = (payload as Record<string, unknown>).error
  if (typeof error !== "string") return false

  if (response.status === 401 && error === "authentication required") {
    return true
  }
  if (
    response.status === 403 &&
    (error === "step_up_required" ||
      error === "protected_secret_transport_unavailable")
  ) {
    return true
  }
  return (
    error === "sensitive_request_rejected" &&
    [400, 413, 415, 428, 503].includes(response.status)
  )
}

export function NativeWireGuardImportFields({
  displayName,
  mode,
  readiness,
  requiredGuards = [],
  existingInterfaces = [],
  linkRequired = false,
  linkValue = "",
  onLinkChange,
  onAliasSuggestionChange,
  onImportPending,
  onNativeUriActiveChange,
  onImportedIdentityChange,
  onSubscriptionDocument,
}: {
  readonly displayName?: string
  readonly mode: "link" | "file"
  readonly readiness?: NdmsNativeImportReadiness
  readonly requiredGuards?: readonly NdmsInterfaceInventoryResponseRequiredGuardsItem[]
  readonly existingInterfaces?: readonly NdmsTunnelInterface[]
  readonly linkRequired?: boolean
  readonly linkValue?: string
  readonly onLinkChange?: (value: string) => void
  readonly onAliasSuggestionChange?: (suggestion?: string) => void
  readonly onImportPending?: (endpointHost?: string) => void
  readonly onNativeUriActiveChange?: (active: boolean) => void
  readonly onImportedIdentityChange?: (
    identity: NativeWireGuardImportedIdentity | null
  ) => void
  // A chosen file that is not a WireGuard configuration. The modal takes it
  // from here to the subscription planner rather than this component deciding
  // what it is.
  readonly onSubscriptionDocument?: (text: string, fileName: string) => void
}) {
  const authStatus = useTrustedAuthStatus()
  const protectedTransport =
    currentNativeWireGuardImportTransportIsProtected(authStatus)

  return (
    <NativeWireGuardImportFieldsContent
      displayName={displayName}
      existingInterfaces={existingInterfaces}
      linkRequired={linkRequired}
      linkValue={linkValue}
      mode={mode}
      onLinkChange={onLinkChange}
      onAliasSuggestionChange={onAliasSuggestionChange}
      onImportPending={onImportPending}
      onNativeUriActiveChange={onNativeUriActiveChange}
      onImportedIdentityChange={onImportedIdentityChange}
      onSubscriptionDocument={onSubscriptionDocument}
      protectedTransport={protectedTransport}
      readiness={readiness}
      requiredGuards={requiredGuards}
    />
  )
}

/**
 * Raw text is scoped to the asynchronous intake call and parsed only in this
 * browser. Pasted URI text is intercepted before it enters the textarea or
 * React state. Native material is parsed only in authenticated HTTPS or in a
 * short-lived local connection proven by the server from socket, NDMS and
 * route evidence; keys never enter React state, storage, URLs, logs or errors.
 * Ordinary sing-box links remain editable when native import is unavailable.
 */
function NativeWireGuardImportFieldsContent({
  displayName,
  mode,
  readiness,
  requiredGuards = [],
  existingInterfaces = [],
  linkRequired,
  linkValue,
  onLinkChange,
  onAliasSuggestionChange,
  onImportPending,
  onNativeUriActiveChange,
  onImportedIdentityChange,
  onSubscriptionDocument,
  protectedTransport,
}: {
  readonly displayName?: string
  readonly mode: "link" | "file"
  readonly readiness?: NdmsNativeImportReadiness
  readonly requiredGuards?: readonly NdmsInterfaceInventoryResponseRequiredGuardsItem[]
  readonly existingInterfaces?: readonly NdmsTunnelInterface[]
  readonly linkRequired: boolean
  readonly linkValue: string
  readonly onLinkChange?: (value: string) => void
  readonly onAliasSuggestionChange?: (suggestion?: string) => void
  readonly onImportPending?: (endpointHost?: string) => void
  readonly onNativeUriActiveChange?: (active: boolean) => void
  readonly onImportedIdentityChange?: (
    identity: NativeWireGuardImportedIdentity | null
  ) => void
  // A chosen file that is not a WireGuard configuration. The modal takes it
  // from here to the subscription planner rather than this component deciding
  // what it is.
  readonly onSubscriptionDocument?: (text: string, fileName: string) => void
  readonly protectedTransport: boolean
}) {
  const { t, i18n } = useTranslation()
  const queryClient = useQueryClient()
  const inputRef = useRef<HTMLInputElement>(null)
  const dropzoneRef = useRef<HTMLDivElement>(null)
  const linkInputRef = useRef<HTMLTextAreaElement>(null)
  const summaryRef = useRef<HTMLDivElement>(null)
  const readGateRef = useRef(createNativeWireGuardFileReadGate())
  const mountedRef = useRef(true)
  const submissionActiveRef = useRef(false)
  const vaultRef = useRef<NativeWireGuardSecretVault | null>(null)
  if (vaultRef.current === null) {
    vaultRef.current = createNativeWireGuardSecretVault()
  }
  const [dragActive, setDragActive] = useState(false)
  const [state, setState] = useState<ImportState>({ status: "empty" })
  const [operation, setOperation] = useState<ImportOperationState>(() => {
    const persistedLock = readNativeWireGuardImportLock()
    return persistedLock === "unknown" || persistedLock === "pending"
      ? { status: "unknown" }
      : persistedLock === "recovery_required"
        ? { status: "recovery-locked" }
        : { status: "idle" }
  })
  const [ownerRiskAccepted, setOwnerRiskAccepted] = useState(false)
  const [transportBlocked, setTransportBlocked] = useState(false)
  const admissionRevision = nativeWireGuardImportAdmissionRevision({
    protectedTransport,
    readiness,
    requiredGuards,
    existingInterfaces,
  })
  const admissionRevisionRef = useRef(admissionRevision)
  const recoveryLocked =
    operation.status === "unknown" ||
    operation.status === "recovery-locked" ||
    (operation.status === "result" && operation.outcome === "recovery_required")
  const intakeLocked = nativeWireGuardImportIntakeIsLocked(operation)
  const completedIdentity =
    operation.status === "result" && operation.outcome === "completed"
      ? provedCompletedNativeImportIdentity(operation.result)
      : null
  const completedIdentityReportedRef = useRef<string | undefined>(undefined)
  const awaitingRecoveredCompletionRef = useRef(false)
  const importAliasSuggestion =
    state.status === "ready"
      ? suggestNativeWireGuardImportAlias({
          fileName: state.aliasSourceFileName,
          endpointHost: state.preview.endpoint_host,
        })
      : undefined

  useEffect(() => {
    onAliasSuggestionChange?.(importAliasSuggestion)
    return () => onAliasSuggestionChange?.(undefined)
  }, [importAliasSuggestion, onAliasSuggestionChange])

  const reportImportedIdentity = useCallback(
    (identity: NativeWireGuardImportedIdentity): boolean => {
      const key = `${identity.firmwareInterface}\n${identity.kernelInterface}\n${identity.kind}`
      if (completedIdentityReportedRef.current === key) return true
      completedIdentityReportedRef.current = key
      onImportedIdentityChange?.(identity)
      return true
    },
    [onImportedIdentityChange]
  )

  useEffect(
    () =>
      registerActiveNativeWireGuardImportCompletion((identity) => {
        if (identity === null) {
          awaitingRecoveredCompletionRef.current = false
          return true
        }
        if (!mountedRef.current || !awaitingRecoveredCompletionRef.current) {
          return false
        }
        awaitingRecoveredCompletionRef.current = false
        return reportImportedIdentity(identity)
      }),
    [reportImportedIdentity]
  )

  const resetOperation = () => {
    awaitingRecoveredCompletionRef.current = false
    setOwnerRiskAccepted(false)
    setOperation({ status: "idle" })
    onImportedIdentityChange?.(null)
  }

  const clear = () => {
    if (intakeLocked) return
    readGateRef.current.invalidate()
    vaultRef.current?.clear()
    setState({ status: "empty" })
    resetOperation()
    setTransportBlocked(false)
    onNativeUriActiveChange?.(false)
    if (inputRef.current) inputRef.current.value = ""
    queueMicrotask(() => {
      ;(mode === "file" ? dropzoneRef.current : linkInputRef.current)?.focus()
    })
  }

  useEffect(() => {
    mountedRef.current = true
    // React StrictMode intentionally runs mount cleanup/setup twice in
    // development. Recreate the disposed vault on each real effect setup so
    // the simulated cleanup cannot permanently revoke the live component.
    vaultRef.current = createNativeWireGuardSecretVault()
    const effectVault = vaultRef.current
    const effectReadGate = readGateRef.current
    return () => {
      mountedRef.current = false
      effectReadGate.invalidate()
      effectVault.dispose()
    }
  }, [])

  useEffect(() => {
    if (protectedTransport) return
    readGateRef.current.invalidate()
    vaultRef.current?.revoke()
    queueMicrotask(() => {
      setOwnerRiskAccepted(false)
      setOperation((current) =>
        nativeWireGuardImportOperationSurvivesContextChange(current)
          ? current
          : { status: "idle" }
      )
      onImportedIdentityChange?.(null)
      setState((current) =>
        current.status === "empty" ? current : { status: "empty" }
      )
    })
  }, [onImportedIdentityChange, protectedTransport])

  useEffect(() => {
    if (admissionRevisionRef.current === admissionRevision) return
    admissionRevisionRef.current = admissionRevision
    readGateRef.current.invalidate()
    vaultRef.current?.clear()
    queueMicrotask(() => {
      setOwnerRiskAccepted(false)
      setOperation((current) =>
        nativeWireGuardImportOperationSurvivesContextChange(current)
          ? current
          : { status: "idle" }
      )
      setState({ status: "empty" })
      onImportedIdentityChange?.(null)
    })
    if (inputRef.current) inputRef.current.value = ""
  }, [admissionRevision, onImportedIdentityChange])

  useEffect(
    () =>
      subscribeNativeWireGuardImportLock((reason) => {
        if (reason === null) {
          if (submissionActiveRef.current) return
          readGateRef.current.invalidate()
          vaultRef.current?.revoke()
          setOwnerRiskAccepted(false)
          setState({ status: "empty" })
          onImportedIdentityChange?.(null)
          setOperation({ status: "idle" })
          return
        }
        readGateRef.current.invalidate()
        vaultRef.current?.revoke()
        setOwnerRiskAccepted(false)
        setState({ status: "empty" })
        onImportedIdentityChange?.(null)
        setOperation(
          reason === "recovery_required"
            ? { status: "recovery-locked" }
            : { status: "unknown" }
        )
      }),
    [onImportedIdentityChange]
  )

  useEffect(() => {
    if (
      state.status === "error" ||
      operation.status === "preflight-error" ||
      operation.status === "selection-expired" ||
      operation.status === "unknown" ||
      operation.status === "recovery-locked" ||
      operation.status === "result"
    ) {
      queueMicrotask(() => summaryRef.current?.focus())
    }
  }, [operation.status, state.status])

  const analyzeText = async ({
    text,
    generation,
    fileName,
    fileSize,
    aliasSourceFileName,
    ticket,
  }: {
    readonly text: string
    readonly generation: number
    readonly fileName: string
    readonly fileSize: number
    readonly aliasSourceFileName?: string
    readonly ticket: NativeWireGuardSecretTicket
  }) => {
    const textIssue = validateNativeWireGuardImportText(text)
    if (textIssue) {
      if (readGateRef.current.isCurrent(generation)) {
        vaultRef.current?.clear()
        setState({ status: "error", fileName, code: textIssue })
      }
      return
    }
    const preliminary = await parseNativeWireGuardInputPreview(text)
    if (!readGateRef.current.isCurrent(generation)) return
    if (!preliminary.ok) {
      vaultRef.current?.clear()
      setState({
        status: "error",
        fileName,
        code: preliminary.code,
        ...(preliminary.line ? { line: preliminary.line } : {}),
      })
      return
    }

    const secret = new TextEncoder().encode(text)
    try {
      if (!vaultRef.current?.replace(ticket, secret)) return
    } catch {
      if (readGateRef.current.isCurrent(generation)) {
        setState({
          status: "error",
          fileName,
          code: "secret-buffer-failed",
        })
      }
      return
    }

    setState({
      status: "ready",
      fileName,
      fileSize,
      ...(aliasSourceFileName ? { aliasSourceFileName } : {}),
      preview: preliminary.preview,
      ticket,
    })
  }

  const readFile = async (file: File) => {
    if (intakeLocked) return
    const generation = readGateRef.current.begin()
    const ticket = vaultRef.current!.begin()
    resetOperation()
    const fileIssue = validateNativeWireGuardImportFile(file)
    if (fileIssue) {
      if (readGateRef.current.isCurrent(generation)) {
        vaultRef.current?.clear()
        setState({ status: "error", fileName: file.name, code: fileIssue })
      }
      return
    }
    setState({ status: "loading", fileName: file.name })

    let text: string
    try {
      // This local variable is the only component scope with raw material.
      text = await file.text()
    } catch {
      if (readGateRef.current.isCurrent(generation)) {
        vaultRef.current?.clear()
        setState({ status: "error", fileName: file.name, code: "read-failed" })
      }
      return
    }
    if (!readGateRef.current.isCurrent(generation)) return

    // One file picker, two kinds of file. A WireGuard configuration is
    // recognised positively by its section header; anything else goes to the
    // subscription planner, which is the component that can actually name what
    // a document is - a link list, a base64 list, a sing-box config - and says
    // so. Guessing "not a subscription" here would send readable subscriptions
    // into the WireGuard parser to fail with the wrong message.
    const sensitiveKind = classifyNativeWireGuardSensitiveInput(text)
    const lowerFileName = file.name.trim().toLowerCase()
    const nativeFile =
      lowerFileName.endsWith(".conf") ||
      lowerFileName.endsWith(".vpn") ||
      sensitiveKind !== undefined ||
      looksLikeWireGuardConfig(text)
    if (onSubscriptionDocument && !nativeFile) {
      readGateRef.current.invalidate()
      vaultRef.current?.clear()
      setState({ status: "empty" })
      onSubscriptionDocument(text, file.name)
      return
    }

    const normalized = sensitiveKind
      ? normalizeNativeWireGuardSensitiveInput(text, sensitiveKind)
      : text
    await analyzeText({
      text: normalized,
      generation,
      fileName: file.name,
      fileSize: utf8ByteLengthAndWipe(normalized),
      aliasSourceFileName: file.name,
      ticket,
    })
  }

  const analyzeSensitiveInput = async (
    text: string,
    kind: "vpn-uri" | "config"
  ) => {
    if (intakeLocked) return
    onNativeUriActiveChange?.(true)
    onLinkChange?.("")
    if (!protectedTransport) {
      readGateRef.current.invalidate()
      vaultRef.current?.revoke()
      resetOperation()
      setState({ status: "empty" })
      setTransportBlocked(true)
      return
    }
    setTransportBlocked(false)
    const generation = readGateRef.current.begin()
    const ticket = vaultRef.current!.begin()
    resetOperation()
    const fileName = t("transports.nativeImport.pastedInput")
    setState({ status: "loading", fileName })
    const normalized = normalizeNativeWireGuardSensitiveInput(text, kind)
    await analyzeText({
      text: normalized,
      generation,
      fileName,
      fileSize: utf8ByteLengthAndWipe(normalized),
      ticket,
    })
  }

  const chooseFiles = (files: FileList | null) => {
    if (intakeLocked) return
    if (!files?.length) return
    // FileList may be live: detach every File reference before clearing the
    // native input, otherwise some browsers empty the list underneath us.
    const selectedFiles = Array.from(files)
    // Browsers do not fire `change` for the same path twice unless the native
    // input is reset. State keeps the safe filename/preview separately.
    if (inputRef.current) inputRef.current.value = ""
    if (selectedFiles.length !== 1 || !selectedFiles[0]) {
      readGateRef.current.invalidate()
      vaultRef.current?.clear()
      resetOperation()
      setState({ status: "error", code: "single-file-only" })
      return
    }
    void readFile(selectedFiles[0])
  }

  const onDrop = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault()
    setDragActive(false)
    if (intakeLocked) return
    if (event.dataTransfer.files.length > 0) {
      chooseFiles(event.dataTransfer.files)
    }
  }
  const onUriPaste = (event: ClipboardEvent<HTMLTextAreaElement>) => {
    const text = event.clipboardData.getData("text/plain")
    const kind = classifyNativeWireGuardSensitiveInput(text)
    if (!kind) return
    event.preventDefault()
    void analyzeSensitiveInput(text, kind)
  }
  const onLinkInput = (value: string) => {
    if (intakeLocked) return
    const kind = classifyNativeWireGuardSensitiveInput(value)
    if (kind) {
      void analyzeSensitiveInput(value, kind)
      return
    }
    readGateRef.current.invalidate()
    vaultRef.current?.clear()
    resetOperation()
    setState({ status: "empty" })
    setTransportBlocked(false)
    onNativeUriActiveChange?.(false)
    onLinkChange?.(value)
  }
  const openPicker = () => {
    if (!intakeLocked) inputRef.current?.click()
  }
  const onDropzoneKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (!intakeLocked && (event.key === "Enter" || event.key === " ")) {
      event.preventDefault()
      openPicker()
    }
  }

  const submitImport = async () => {
    if (
      state.status !== "ready" ||
      !displayName?.trim() ||
      !ownerRiskAccepted ||
      recoveryLocked ||
      submissionActiveRef.current ||
      (operation.status !== "idle" && operation.status !== "preflight-error")
    ) {
      return
    }

    let pendingStarted = false
    submissionActiveRef.current = true
    setOperation({ status: "preflighting" })
    try {
      const leaseResult = await runWithNativeMutationLease(
        "import",
        async ({ beginPending }) => {
          try {
            const response = await postNdmsNativeImportSecretOnce({
              displayName,
              vault: vaultRef.current!,
              ticket: state.ticket,
              preflight: async (binding) => {
                const verdict = await preflightNdmsNativeImport({ binding })
                if (verdict !== "admitted") return verdict
                if (!mountedRef.current || !beginPending()) return "denied"
                pendingStarted = true
                awaitingRecoveredCompletionRef.current = true
                onImportPending?.(state.preview.endpoint_host)
                setOperation({ status: "sending" })
                return verdict
              },
            })
            const payload = await response.json().catch(() => null)
            if (
              !response.ok &&
              importWasDefinitelyNotStarted(response, payload)
            ) {
              return {
                disposition: { state: "clear" } as const,
                value: { status: "not-imported" } as ImportOperationState,
              }
            }
            const result = response.ok
              ? parseNdmsNativeImportResult(payload)
              : null
            if (!result) {
              return {
                disposition: { state: "unknown" } as const,
                value: { status: "unknown" } as ImportOperationState,
              }
            }

            const outcome = ndmsNativeImportOutcome(result)
            return {
              disposition:
                outcome === "recovery_required"
                  ? ({ state: "recovery", recovery: "import" } as const)
                  : ({ state: "clear" } as const),
              value: {
                status: "result",
                outcome,
                result,
              } as ImportOperationState,
            }
          } catch (error) {
            if (error instanceof NativeSecretTransportError) {
              if (
                error.code === "preflight_denied" ||
                error.code === "preflight_failed"
              ) {
                return {
                  disposition: { state: "not_started" } as const,
                  value: {
                    status: "preflight-error",
                  } as ImportOperationState,
                }
              }
              if (error.code === "secret_unavailable") {
                return {
                  disposition: { state: "clear" } as const,
                  value: {
                    status: "selection-expired",
                  } as ImportOperationState,
                }
              }
            }
            return {
              disposition: { state: "unknown" } as const,
              value: { status: "unknown" } as ImportOperationState,
            }
          }
        }
      )

      if (!mountedRef.current) return
      if (leaseResult.status === "completed") {
        const nextOperation = leaseResult.value
        if (
          nextOperation.status !== "result" ||
          nextOperation.outcome !== "recovery_required"
        ) {
          awaitingRecoveredCompletionRef.current = false
        }
        if (
          nextOperation.status === "result" &&
          nextOperation.outcome === "completed"
        ) {
          const identity = provedCompletedNativeImportIdentity(
            nextOperation.result
          )
          if (identity) reportImportedIdentity(identity)
        }
        setOperation(nextOperation)
      } else {
        if (!pendingStarted) awaitingRecoveredCompletionRef.current = false
        const durableLock = readNativeWireGuardImportLock()
        setOperation(
          durableLock === "recovery_required"
            ? { status: "recovery-locked" }
            : { status: "unknown" }
        )
      }
    } finally {
      submissionActiveRef.current = false
      if (pendingStarted) {
        await Promise.all([
          queryClient.invalidateQueries({
            queryKey: queryKeys.ndmsInterfaceInventory(),
          }),
          queryClient.invalidateQueries({
            queryKey: queryKeys.runtimeInterfaces(),
          }),
        ])
      }
    }
  }

  return (
    <section className="space-y-3">
      {mode === "file" && !protectedTransport ? (
        <Alert variant="destructive">
          <ShieldAlertIcon />
          <AlertTitle>
            {t("transports.nativeImport.transportBlockedTitle")}
          </AlertTitle>
          <AlertDescription>
            {t("transports.nativeImport.transportBlockedDescription")}
          </AlertDescription>
        </Alert>
      ) : mode === "file" ? (
        <>
          <p className="text-sm text-muted-foreground">
            {t("transports.nativeImport.fileDescription")}
          </p>
          <input
            accept=".conf,.vpn,text/plain"
            className="hidden"
            disabled={intakeLocked}
            onChange={(event: ChangeEvent<HTMLInputElement>) =>
              chooseFiles(event.target.files)
            }
            ref={inputRef}
            type="file"
          />
          <div
            aria-disabled={intakeLocked}
            aria-describedby="native-wireguard-import-hint"
            aria-label={t("transports.nativeImport.dropzoneLabel")}
            className={cn(
              "flex min-h-36 cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-input bg-muted/25 px-4 py-6 text-center transition-colors outline-none hover:border-primary hover:bg-primary/5 focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/20",
              dragActive && "border-primary bg-primary/10",
              intakeLocked && "cursor-not-allowed opacity-60"
            )}
            onClick={() => {
              if (!intakeLocked) openPicker()
            }}
            onDragEnter={(event) => {
              event.preventDefault()
              setDragActive(true)
            }}
            onDragLeave={(event) => {
              event.preventDefault()
              if (
                !event.currentTarget.contains(
                  event.relatedTarget as Node | null
                )
              ) {
                setDragActive(false)
              }
            }}
            onDragOver={(event) => {
              event.preventDefault()
              event.dataTransfer.dropEffect = "copy"
            }}
            onDrop={onDrop}
            onKeyDown={onDropzoneKeyDown}
            ref={dropzoneRef}
            role="button"
            tabIndex={intakeLocked ? -1 : 0}
          >
            <FileUpIcon className="size-6 text-primary" />
            <span className="font-medium">
              {t("transports.nativeImport.dropzone")}
            </span>
            <span
              className="text-xs text-muted-foreground"
              id="native-wireguard-import-hint"
            >
              {t("transports.nativeImport.fileHint", {
                confSize: NATIVE_WIREGUARD_CONF_MAX_BYTES / 1024,
                uriSize: NATIVE_WIREGUARD_URI_MAX_BYTES / 1024,
              })}
            </span>
          </div>
        </>
      ) : (
        <div className="space-y-1.5">
          <label
            className="text-sm font-medium"
            htmlFor="native-wireguard-uri-paste"
          >
            {t("transports.form.shareLink")}
          </label>
          <textarea
            aria-describedby="native-wireguard-uri-paste-hint"
            className="min-h-28 w-full resize-y rounded-md border border-input bg-background px-3 py-2 font-mono text-xs outline-none placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/20"
            id="native-wireguard-uri-paste"
            disabled={intakeLocked}
            onChange={(event) => onLinkInput(event.target.value)}
            onPaste={onUriPaste}
            placeholder="vless://…  vmess://…  trojan://…  vpn://…"
            required={linkRequired}
            ref={linkInputRef}
            value={linkValue}
          />
          <p
            className="text-xs text-muted-foreground"
            id="native-wireguard-uri-paste-hint"
          >
            {t("transports.form.shareLinkHint")}
          </p>
        </div>
      )}

      {transportBlocked ? (
        <Alert variant="destructive">
          <ShieldAlertIcon />
          <AlertTitle>
            {t("transports.nativeImport.transportBlockedTitle")}
          </AlertTitle>
          <AlertDescription>
            {t("transports.nativeImport.transportBlockedDescription")}
          </AlertDescription>
        </Alert>
      ) : null}

      {state.status === "loading" ? (
        <p aria-live="polite" className="text-sm text-muted-foreground">
          {t("transports.nativeImport.analyzing", { name: state.fileName })}
        </p>
      ) : null}

      {state.status === "error" ? (
        <div ref={summaryRef} role="alert" tabIndex={-1}>
          <Alert role="presentation" variant="destructive">
            <ShieldAlertIcon />
            <AlertTitle>{t("transports.nativeImport.errorTitle")}</AlertTitle>
            <AlertDescription>
              {state.fileName ? (
                <p className="font-medium break-all text-current">
                  {state.fileName}
                </p>
              ) : null}
              <p>{nativeImportErrorLabel(state.code, state.line, t)}</p>
            </AlertDescription>
          </Alert>
        </div>
      ) : null}

      {state.status === "ready" ? (
        <div className="space-y-3 rounded-lg border border-border p-3">
          <div className="flex min-w-0 flex-wrap items-start justify-between gap-3">
            <div className="flex min-w-0 items-center gap-2">
              <FileKey2Icon className="size-5 shrink-0 text-primary" />
              <span className="min-w-0">
                <span className="block truncate font-medium">
                  {state.fileName}
                </span>
                <span className="block text-xs text-muted-foreground">
                  {formatFileSize(
                    state.fileSize,
                    i18n.resolvedLanguage ?? i18n.language
                  )}
                </span>
              </span>
            </div>
            <Button
              aria-label={t("transports.nativeImport.clear")}
              className="min-h-11 min-w-11"
              disabled={intakeLocked}
              onClick={clear}
              size="icon"
              variant="ghost"
            >
              <XIcon />
            </Button>
          </div>

          <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-2 lg:grid-cols-4">
            <PreviewField
              label={t("transports.nativeImport.preview.protocol")}
              value={
                state.preview.kind === "amnezia_wireguard"
                  ? "AmneziaWG"
                  : "WireGuard"
              }
            />
            <PreviewField
              label={t("transports.nativeImport.preview.addresses")}
              value={String(state.preview.address_count)}
            />
            <PreviewField
              label={t("transports.nativeImport.preview.dns")}
              value={String(state.preview.dns_count)}
            />
            <PreviewField
              label={t("transports.nativeImport.preview.peers")}
              value={String(state.preview.peer_count)}
            />
            <PreviewField
              label={t("transports.nativeImport.preview.allowedIps")}
              value={String(state.preview.allowed_ip_count)}
            />
            <PreviewField
              label={t("transports.nativeImport.preview.privateKey")}
              value={
                state.preview.private_key_present
                  ? t("transports.nativeImport.preview.presentRedacted")
                  : t("transports.nativeImport.preview.absent")
              }
            />
            <PreviewField
              label={t("transports.nativeImport.preview.presharedKeys")}
              value={String(state.preview.preshared_key_peer_count)}
            />
            <PreviewField
              label={t("transports.nativeImport.preview.endpoint")}
              value={
                state.preview.endpoint_host && state.preview.endpoint_port
                  ? formatEndpoint(
                      state.preview.endpoint_host,
                      state.preview.endpoint_port
                    )
                  : t("transports.nativeImport.preview.hiddenOrMultiple")
              }
            />
            <PreviewField
              label={t("transports.nativeImport.preview.keepalive")}
              value={
                state.preview.persistent_keepalive === undefined
                  ? t("common.noneShort")
                  : t("transports.nativeImport.preview.seconds", {
                      count: state.preview.persistent_keepalive,
                    })
              }
            />
            <PreviewField
              label={t("transports.nativeImport.preview.listenPort")}
              value={
                state.preview.listen_port === undefined
                  ? t("common.noneShort")
                  : String(state.preview.listen_port)
              }
            />
            <PreviewField
              label={t("transports.nativeImport.preview.mtu")}
              value={
                state.preview.mtu === undefined
                  ? t("common.noneShort")
                  : String(state.preview.mtu)
              }
            />
            <PreviewField
              label={t("transports.nativeImport.preview.aliasSuggestion")}
              value={importAliasSuggestion ?? t("common.noneShort")}
            />
            <PreviewField
              label={t("transports.nativeImport.preview.amneziaParameters")}
              value={
                state.preview.amnezia_parameter_names.length
                  ? state.preview.amnezia_parameter_names.join(", ")
                  : t("common.noneShort")
              }
            />
          </dl>
          {findNativeWireGuardAliasConflict(
            importAliasSuggestion,
            existingInterfaces
          ) ? (
            <Alert variant="warning">
              <ShieldAlertIcon />
              <AlertTitle>
                {t("transports.nativeImport.aliasConflictTitle")}
              </AlertTitle>
              <AlertDescription>
                {t("transports.nativeImport.aliasConflictDescription")}
              </AlertDescription>
            </Alert>
          ) : null}
        </div>
      ) : null}

      {state.status === "ready" &&
      (operation.status === "idle" ||
        operation.status === "preflight-error" ||
        operation.status === "preflighting" ||
        operation.status === "sending") ? (
        <div className="space-y-3 rounded-lg border border-warning/40 bg-warning/5 p-3">
          {!displayName?.trim() ? (
            <p className="text-sm font-medium text-foreground">
              {t("transports.nativeImport.displayNameRequired")}
            </p>
          ) : null}
          <label className="flex min-h-11 cursor-pointer items-start gap-3 rounded-md p-1 text-sm">
            <input
              checked={ownerRiskAccepted}
              className="mt-0.5 size-5 shrink-0 accent-primary"
              disabled={
                operation.status === "preflighting" ||
                operation.status === "sending"
              }
              onChange={(event) => setOwnerRiskAccepted(event.target.checked)}
              type="checkbox"
            />
            <span className="min-w-0 break-words">
              {t("transports.nativeImport.ownerRiskConsent")}
            </span>
          </label>
          <p className="text-xs break-words text-muted-foreground">
            {t("transports.nativeImport.ownerRiskExplanation")}
          </p>
          {readiness ? (
            <p className="text-xs break-words text-muted-foreground">
              {t("transports.nativeImport.createOnlyRange", {
                first: `${readiness.eligible_returned_targets.prefix}${readiness.eligible_returned_targets.first_index}`,
                last: `${readiness.eligible_returned_targets.prefix}${readiness.eligible_returned_targets.last_index}`,
              })}
            </p>
          ) : null}
          <div className="flex flex-wrap items-center gap-3">
            <Button
              className="min-h-11 whitespace-normal"
              disabled={
                !displayName?.trim() ||
                !ownerRiskAccepted ||
                operation.status === "preflighting" ||
                operation.status === "sending"
              }
              onClick={() => void submitImport()}
              type="button"
            >
              {operation.status === "preflighting"
                ? t("transports.nativeImport.preflighting")
                : operation.status === "sending"
                  ? t("transports.nativeImport.sending")
                  : t("transports.nativeImport.apply")}
            </Button>
            {operation.status === "preflighting" ||
            operation.status === "sending" ? (
              <span
                aria-live="polite"
                className="text-sm text-muted-foreground"
              >
                {t(
                  operation.status === "preflighting"
                    ? "transports.nativeImport.preflightStatus"
                    : "transports.nativeImport.sendingStatus"
                )}
              </span>
            ) : null}
          </div>
        </div>
      ) : null}

      {operation.status === "preflight-error" ? (
        <div ref={summaryRef} role="alert" tabIndex={-1}>
          <Alert role="presentation" variant="warning">
            <ShieldAlertIcon />
            <AlertTitle>
              {t("transports.nativeImport.preflightFailedTitle")}
            </AlertTitle>
            <AlertDescription>
              {t("transports.nativeImport.preflightFailedDescription")}
            </AlertDescription>
          </Alert>
        </div>
      ) : null}

      {operation.status === "selection-expired" ? (
        <div ref={summaryRef} role="alert" tabIndex={-1}>
          <Alert role="presentation" variant="destructive">
            <ShieldAlertIcon />
            <AlertTitle>
              {t("transports.nativeImport.selectionExpiredTitle")}
            </AlertTitle>
            <AlertDescription>
              {t("transports.nativeImport.selectionExpiredDescription")}
            </AlertDescription>
          </Alert>
        </div>
      ) : null}

      {operation.status === "not-imported" ? (
        <div ref={summaryRef} role="alert" tabIndex={-1}>
          <Alert role="presentation" variant="warning">
            <ShieldAlertIcon />
            <AlertTitle>
              {t("transports.nativeImport.notImportedTitle")}
            </AlertTitle>
            <AlertDescription>
              {t("transports.nativeImport.notImportedDescription")}
            </AlertDescription>
          </Alert>
        </div>
      ) : null}

      {operation.status === "unknown" ? (
        <div ref={summaryRef} role="alert" tabIndex={-1}>
          <Alert role="presentation" variant="destructive">
            <ShieldAlertIcon />
            <AlertTitle>{t("transports.nativeImport.unknownTitle")}</AlertTitle>
            <AlertDescription className="space-y-2">
              <p>{t("transports.nativeImport.unknownDescription")}</p>
              <p>{t("transports.nativeImport.noBlindRetry")}</p>
            </AlertDescription>
          </Alert>
        </div>
      ) : null}

      {operation.status === "recovery-locked" ? (
        <div ref={summaryRef} role="alert" tabIndex={-1}>
          <Alert role="presentation" variant="destructive">
            <ShieldAlertIcon />
            <AlertTitle>
              {t("transports.nativeImport.results.recovery_requiredTitle")}
            </AlertTitle>
            <AlertDescription className="space-y-2">
              <p>
                {t(
                  "transports.nativeImport.results.recovery_requiredDescription"
                )}
              </p>
              <p>{t("transports.nativeImport.noBlindRetry")}</p>
            </AlertDescription>
          </Alert>
        </div>
      ) : null}

      {operation.status === "result" ? (
        <div
          aria-live={operation.outcome === "completed" ? "polite" : undefined}
          ref={summaryRef}
          role={operation.outcome === "completed" ? "status" : "alert"}
          tabIndex={-1}
        >
          <Alert
            role="presentation"
            variant={operation.outcome === "completed" ? "default" : "warning"}
          >
            {operation.outcome === "completed" ? (
              <CheckCircle2Icon />
            ) : (
              <ShieldAlertIcon />
            )}
            <AlertTitle>
              {operation.outcome === "completed"
                ? t("transports.nativeImport.results.completedTitle")
                : operation.outcome === "blocked"
                  ? t("transports.nativeImport.results.blockedTitle")
                  : t("transports.nativeImport.results.recovery_requiredTitle")}
            </AlertTitle>
            <AlertDescription className="space-y-3">
              <p>
                {operation.outcome === "completed"
                  ? t("transports.nativeImport.results.completedDescription")
                  : operation.outcome === "blocked"
                    ? t("transports.nativeImport.results.blockedDescription")
                    : t(
                        "transports.nativeImport.results.recovery_requiredDescription"
                      )}
              </p>
              {operation.outcome === "completed" ? (
                <>
                  <dl className="grid gap-2 text-sm sm:grid-cols-2">
                    <PreviewField
                      label={t(
                        "transports.nativeImport.results.firmwareInterface"
                      )}
                      value={completedIdentity?.firmwareInterface ?? ""}
                    />
                    <PreviewField
                      label={t(
                        "transports.nativeImport.results.kernelInterface"
                      )}
                      value={completedIdentity?.kernelInterface ?? ""}
                    />
                  </dl>
                  <p className="font-medium">
                    {t("transports.nativeImport.results.runningOnly")}
                  </p>
                </>
              ) : (
                <>
                  {operation.outcome === "blocked" ? (
                    <p className="font-mono text-xs break-all">
                      {t("transports.nativeImport.results.stop", {
                        stop: operation.result.stop,
                      })}
                    </p>
                  ) : null}
                  {operation.outcome === "recovery_required" ? (
                    <p>{t("transports.nativeImport.noBlindRetry")}</p>
                  ) : null}
                </>
              )}
            </AlertDescription>
          </Alert>
        </div>
      ) : null}
    </section>
  )
}

function PreviewField({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="font-medium break-all" title={value}>
        {value}
      </dd>
    </div>
  )
}

function formatFileSize(bytes: number, locale: string): string {
  return new Intl.NumberFormat(locale, {
    style: "unit",
    unit: "kilobyte",
    maximumFractionDigits: 1,
  }).format(bytes / 1024)
}

function utf8ByteLengthAndWipe(value: string): number {
  const encoded = new TextEncoder().encode(value)
  try {
    return encoded.byteLength
  } finally {
    encoded.fill(0)
  }
}

function nativeImportErrorLabel(
  code:
    | NativeWireGuardImportFileIssue
    | NativeWireGuardImportErrorCode
    | "secret-buffer-failed",
  line: number | undefined,
  t: (key: string, options?: Record<string, unknown>) => string
): string {
  const options = { line }
  switch (code) {
    case "single-file-only":
      return t("transports.nativeImport.errors.single-file-only", options)
    case "supported-extension-required":
      return t(
        "transports.nativeImport.errors.supported-extension-required",
        options
      )
    case "empty-file":
      return t("transports.nativeImport.errors.empty-file", options)
    case "file-too-large":
      return t("transports.nativeImport.errors.file-too-large", options)
    case "not-text":
      return t("transports.nativeImport.errors.not-text", options)
    case "read-failed":
      return t("transports.nativeImport.errors.read-failed", options)
    case "secret-buffer-failed":
      return t("transports.nativeImport.errors.secret-buffer-failed", options)
    case "input_too_large":
      return t("transports.nativeImport.errors.input_too_large", options)
    case "invalid_encoding":
      return t("transports.nativeImport.errors.invalid_encoding", options)
    case "unsupported_uri":
      return t("transports.nativeImport.errors.unsupported_uri", options)
    case "invalid_base64":
      return t("transports.nativeImport.errors.invalid_base64", options)
    case "invalid_compression":
      return t("transports.nativeImport.errors.invalid_compression", options)
    case "invalid_json":
      return t("transports.nativeImport.errors.invalid_json", options)
    case "unsupported_json_schema":
      return t(
        "transports.nativeImport.errors.unsupported_json_schema",
        options
      )
    case "malformed_line":
      return t("transports.nativeImport.errors.malformed_line", options)
    case "unknown_section":
      return t("transports.nativeImport.errors.unknown_section", options)
    case "duplicate_section":
      return t("transports.nativeImport.errors.duplicate_section", options)
    case "duplicate_field":
      return t("transports.nativeImport.errors.duplicate_field", options)
    case "duplicate_peer":
      return t("transports.nativeImport.errors.duplicate_peer", options)
    case "unknown_field":
      return t("transports.nativeImport.errors.unknown_field", options)
    case "dangerous_directive":
      return t("transports.nativeImport.errors.dangerous_directive", options)
    case "missing_required_field":
      return t("transports.nativeImport.errors.missing_required_field", options)
    case "invalid_field":
      return t("transports.nativeImport.errors.invalid_field", options)
    case "limit_exceeded":
      return t("transports.nativeImport.errors.limit_exceeded", options)
  }
}

function formatEndpoint(host: string, port: number): string {
  return `${host.includes(":") ? `[${host}]` : host}:${port}`
}

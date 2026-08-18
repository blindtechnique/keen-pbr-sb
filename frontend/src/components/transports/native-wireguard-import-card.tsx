import { FileKey2Icon, FileUpIcon, ShieldAlertIcon, XIcon } from "lucide-react"
import {
  useEffect,
  useRef,
  useState,
  type ChangeEvent,
  type ClipboardEvent,
  type DragEvent,
  type KeyboardEvent,
} from "react"
import { useTranslation } from "react-i18next"

import type {
  NdmsInterfaceInventoryResponseRequiredGuardsItem,
  NdmsNativeImportReadiness,
  NdmsNativeImportReadinessBlockersItem,
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
import { parseNativeWireGuardInputPreview } from "@/lib/native-wireguard-vpn-uri-preview"
import { looksLikeWireGuardConfig } from "@/components/transports/subscription-import-model"
import { cn } from "@/lib/utils"

type ImportState =
  | { readonly status: "empty" }
  | { readonly status: "loading"; readonly fileName: string }
  | {
      readonly status: "error"
      readonly fileName?: string
      readonly code:
        | NativeWireGuardImportFileIssue
        | NativeWireGuardImportErrorCode
      readonly line?: number
    }
  | {
      readonly status: "ready"
      readonly fileName: string
      readonly fileSize: number
      readonly aliasSourceFileName?: string
      readonly preview: NativeWireGuardImportPreview
    }

export function NativeWireGuardImportFields({
  mode,
  readiness,
  requiredGuards = [],
  existingInterfaces = [],
  linkRequired = false,
  linkValue = "",
  onLinkChange,
  onNativeUriActiveChange,
  onSubscriptionDocument,
}: {
  readonly mode: "link" | "file"
  readonly readiness?: NdmsNativeImportReadiness
  readonly requiredGuards?: readonly NdmsInterfaceInventoryResponseRequiredGuardsItem[]
  readonly existingInterfaces?: readonly NdmsTunnelInterface[]
  readonly linkRequired?: boolean
  readonly linkValue?: string
  readonly onLinkChange?: (value: string) => void
  readonly onNativeUriActiveChange?: (active: boolean) => void
  // A chosen file that is not a WireGuard configuration. The modal takes it
  // from here to the subscription planner rather than this component deciding
  // what it is.
  readonly onSubscriptionDocument?: (text: string, fileName: string) => void
}) {
  const { t } = useTranslation()
  const authStatus = useTrustedAuthStatus()
  const protectedTransport =
    currentNativeWireGuardImportTransportIsProtected(authStatus)
  if (mode === "file" && !protectedTransport) {
    return (
      <section className="space-y-3">
        <Alert variant="destructive">
          <ShieldAlertIcon />
          <AlertTitle>
            {t("transports.nativeImport.transportBlockedTitle")}
          </AlertTitle>
          <AlertDescription>
            {t("transports.nativeImport.transportBlockedDescription")}
          </AlertDescription>
        </Alert>
      </section>
    )
  }

  return (
    <NativeWireGuardImportFieldsContent
      existingInterfaces={existingInterfaces}
      linkRequired={linkRequired}
      linkValue={linkValue}
      mode={mode}
      onLinkChange={onLinkChange}
      onNativeUriActiveChange={onNativeUriActiveChange}
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
  mode,
  readiness,
  requiredGuards = [],
  existingInterfaces = [],
  linkRequired,
  linkValue,
  onLinkChange,
  onNativeUriActiveChange,
  onSubscriptionDocument,
  protectedTransport,
}: {
  readonly mode: "link" | "file"
  readonly readiness?: NdmsNativeImportReadiness
  readonly requiredGuards?: readonly NdmsInterfaceInventoryResponseRequiredGuardsItem[]
  readonly existingInterfaces?: readonly NdmsTunnelInterface[]
  readonly linkRequired: boolean
  readonly linkValue: string
  readonly onLinkChange?: (value: string) => void
  readonly onNativeUriActiveChange?: (active: boolean) => void
  // A chosen file that is not a WireGuard configuration. The modal takes it
  // from here to the subscription planner rather than this component deciding
  // what it is.
  readonly onSubscriptionDocument?: (text: string, fileName: string) => void
  readonly protectedTransport: boolean
}) {
  const { t, i18n } = useTranslation()
  const inputRef = useRef<HTMLInputElement>(null)
  const readGateRef = useRef(createNativeWireGuardFileReadGate())
  const [dragActive, setDragActive] = useState(false)
  const [state, setState] = useState<ImportState>({ status: "empty" })
  const [transportBlocked, setTransportBlocked] = useState(false)

  const clear = () => {
    readGateRef.current.invalidate()
    setState({ status: "empty" })
    setTransportBlocked(false)
    onNativeUriActiveChange?.(false)
    if (inputRef.current) inputRef.current.value = ""
  }

  useEffect(
    () => () => {
      readGateRef.current.invalidate()
    },
    []
  )

  const analyzeText = async ({
    text,
    generation,
    fileName,
    fileSize,
    aliasSourceFileName,
  }: {
    readonly text: string
    readonly generation: number
    readonly fileName: string
    readonly fileSize: number
    readonly aliasSourceFileName?: string
  }) => {
    const textIssue = validateNativeWireGuardImportText(text)
    if (textIssue) {
      if (readGateRef.current.isCurrent(generation)) {
        setState({ status: "error", fileName, code: textIssue })
      }
      return
    }
    const preliminary = await parseNativeWireGuardInputPreview(text)
    if (!readGateRef.current.isCurrent(generation)) return
    if (!preliminary.ok) {
      setState({
        status: "error",
        fileName,
        code: preliminary.code,
        ...(preliminary.line ? { line: preliminary.line } : {}),
      })
      return
    }

    setState({
      status: "ready",
      fileName,
      fileSize,
      ...(aliasSourceFileName ? { aliasSourceFileName } : {}),
      preview: preliminary.preview,
    })
  }

  const readFile = async (file: File) => {
    const generation = readGateRef.current.begin()
    const fileIssue = validateNativeWireGuardImportFile(file)
    if (fileIssue) {
      if (readGateRef.current.isCurrent(generation)) {
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
    if (onSubscriptionDocument && !looksLikeWireGuardConfig(text)) {
      readGateRef.current.invalidate()
      setState({ status: "empty" })
      onSubscriptionDocument(text, file.name)
      return
    }

    await analyzeText({
      text,
      generation,
      fileName: file.name,
      fileSize: file.size,
      aliasSourceFileName: file.name,
    })
  }

  const analyzeSensitiveInput = async (
    text: string,
    kind: "vpn-uri" | "config"
  ) => {
    onNativeUriActiveChange?.(true)
    onLinkChange?.("")
    if (!protectedTransport) {
      readGateRef.current.invalidate()
      setState({ status: "empty" })
      setTransportBlocked(true)
      return
    }
    setTransportBlocked(false)
    const generation = readGateRef.current.begin()
    const fileName = t("transports.nativeImport.pastedInput")
    setState({ status: "loading", fileName })
    const normalized = normalizeNativeWireGuardSensitiveInput(text, kind)
    await analyzeText({
      text: normalized,
      generation,
      fileName,
      fileSize: new TextEncoder().encode(normalized).byteLength,
    })
  }

  const chooseFiles = (files: FileList | null) => {
    if (!files?.length) return
    // FileList may be live: detach every File reference before clearing the
    // native input, otherwise some browsers empty the list underneath us.
    const selectedFiles = Array.from(files)
    // Browsers do not fire `change` for the same path twice unless the native
    // input is reset. State keeps the safe filename/preview separately.
    if (inputRef.current) inputRef.current.value = ""
    if (selectedFiles.length !== 1 || !selectedFiles[0]) {
      readGateRef.current.invalidate()
      setState({ status: "error", code: "single-file-only" })
      return
    }
    void readFile(selectedFiles[0])
  }

  const onDrop = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault()
    setDragActive(false)
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
    const kind = classifyNativeWireGuardSensitiveInput(value)
    if (kind) {
      void analyzeSensitiveInput(value, kind)
      return
    }
    readGateRef.current.invalidate()
    setState({ status: "empty" })
    setTransportBlocked(false)
    onNativeUriActiveChange?.(false)
    onLinkChange?.(value)
  }
  const openPicker = () => inputRef.current?.click()
  const onDropzoneKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault()
      openPicker()
    }
  }

  return (
    <section className="space-y-3">
      {mode === "file" ? (
        <>
          <p className="text-sm text-muted-foreground">
            {t("transports.nativeImport.fileDescription")}
          </p>
          <input
            accept=".conf,.vpn,text/plain"
            className="hidden"
            onChange={(event: ChangeEvent<HTMLInputElement>) =>
              chooseFiles(event.target.files)
            }
            ref={inputRef}
            type="file"
          />
          <div
            aria-describedby="native-wireguard-import-hint"
            aria-label={t("transports.nativeImport.dropzoneLabel")}
            className={cn(
              "flex min-h-36 cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-input bg-muted/25 px-4 py-6 text-center transition-colors outline-none hover:border-primary hover:bg-primary/5 focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/20",
              dragActive && "border-primary bg-primary/10"
            )}
            onClick={openPicker}
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
            role="button"
            tabIndex={0}
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
            onChange={(event) => onLinkInput(event.target.value)}
            onPaste={onUriPaste}
            placeholder="vless://…  vmess://…  trojan://…  vpn://…"
            required={linkRequired}
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
        <Alert variant="destructive">
          <ShieldAlertIcon />
          <AlertTitle>{t("transports.nativeImport.errorTitle")}</AlertTitle>
          <AlertDescription>
            {state.fileName ? (
              <p className="font-medium text-current">{state.fileName}</p>
            ) : null}
            <p>{nativeImportErrorLabel(state.code, state.line, t)}</p>
          </AlertDescription>
        </Alert>
      ) : null}

      {state.status === "ready" ? (
        <div className="space-y-3 rounded-lg border border-border p-3">
          <div className="flex min-w-0 items-start justify-between gap-3">
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
              onClick={clear}
              size="icon-sm"
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
              value={
                suggestNativeWireGuardImportAlias({
                  fileName: state.aliasSourceFileName,
                  endpointHost: state.preview.endpoint_host,
                }) ?? t("common.noneShort")
              }
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
          <p className="text-xs text-muted-foreground">
            {t("transports.nativeImport.redactedNotice")}
          </p>
          {findNativeWireGuardAliasConflict(
            suggestNativeWireGuardImportAlias({
              fileName: state.aliasSourceFileName,
              endpointHost: state.preview.endpoint_host,
            }),
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

      {mode === "file" || state.status !== "empty" ? (
        <Alert variant="warning">
          <ShieldAlertIcon />
          <AlertTitle>
            {t("transports.nativeImport.applyBlockedTitle")}
          </AlertTitle>
          <AlertDescription className="space-y-2">
            <p>{t("transports.nativeImport.applyBlockedDescription")}</p>
            {readiness ? (
              <p>
                {t("transports.nativeImport.createOnlyRange", {
                  first: `${readiness.eligible_returned_targets.prefix}${readiness.eligible_returned_targets.first_index}`,
                  last: `${readiness.eligible_returned_targets.prefix}${readiness.eligible_returned_targets.last_index}`,
                })}
              </p>
            ) : null}
            {readiness?.blockers.length ? (
              <p>
                {t("transports.nativeImport.readinessBlockers")}: {" "}
                {readiness.blockers
                  .map((blocker) => nativeImportReadinessBlockerLabel(blocker, t))
                  .join("; ")}
              </p>
            ) : null}
            {requiredGuards.length ? (
              <p>
                {t("transports.nativeImport.requiredGuards")}:{" "}
                {requiredGuards
                  .map((guard) => nativeImportGuardLabel(guard, t))
                  .join("; ")}
              </p>
            ) : null}
          </AlertDescription>
        </Alert>
      ) : null}
    </section>
  )
}

function PreviewField({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="truncate font-medium" title={value}>
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

function nativeImportErrorLabel(
  code: NativeWireGuardImportFileIssue | NativeWireGuardImportErrorCode,
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

function nativeImportGuardLabel(
  guard: NdmsInterfaceInventoryResponseRequiredGuardsItem,
  t: (key: string) => string
): string {
  switch (guard) {
    case "typed_rci":
      return t("transports.nativeImport.guards.typed_rci")
    case "automatic_backup":
      return t("transports.nativeImport.guards.automatic_backup")
    case "ownership_check":
      return t("transports.nativeImport.guards.ownership_check")
    case "optimistic_revision":
      return t("transports.nativeImport.guards.optimistic_revision")
  }
}

function nativeImportReadinessBlockerLabel(
  blocker: NdmsNativeImportReadinessBlockersItem,
  t: (key: string) => string
): string {
  switch (blocker) {
    case "writer_disabled":
      return t("transports.nativeImport.blockers.writer_disabled")
    case "allocator_range_unfenced":
      return t("transports.nativeImport.blockers.allocator_range_unfenced")
    case "recovery_journal_not_integrated":
      return t(
        "transports.nativeImport.blockers.recovery_journal_not_integrated"
      )
    case "reconcile_barrier_not_integrated":
      return t(
        "transports.nativeImport.blockers.reconcile_barrier_not_integrated"
      )
  }
}

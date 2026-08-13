import { FileKey2Icon, FileUpIcon, ShieldAlertIcon, XIcon } from "lucide-react"
import {
  useEffect,
  useRef,
  useState,
  type ChangeEvent,
  type DragEvent,
  type KeyboardEvent,
} from "react"
import { useTranslation } from "react-i18next"

import type { NdmsInterfaceInventoryResponseRequiredGuardsItem } from "@/api/generated/model"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { useTrustedAuthStatus } from "@/lib/auth-status-context"
import {
  NATIVE_WIREGUARD_CONF_MAX_BYTES,
  createNativeWireGuardFileReadGate,
  type NativeWireGuardImportFileIssue,
  validateNativeWireGuardImportFile,
  validateNativeWireGuardImportText,
} from "@/lib/native-wireguard-import-file"
import {
  parseNativeWireGuardConfigPreview,
  type NativeWireGuardImportErrorCode,
  type NativeWireGuardImportPreview,
} from "@/lib/native-wireguard-config-preview"
import { currentNativeWireGuardImportTransportIsProtected } from "@/lib/native-wireguard-import-transport"
import { cn } from "@/lib/utils"

type ImportState =
  | { readonly status: "empty" }
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
      readonly preview: NativeWireGuardImportPreview
    }

export function NativeWireGuardImportCard({
  requiredGuards = [],
}: {
  readonly requiredGuards?: readonly NdmsInterfaceInventoryResponseRequiredGuardsItem[]
}) {
  const { t } = useTranslation()
  const authStatus = useTrustedAuthStatus()
  if (!currentNativeWireGuardImportTransportIsProtected(authStatus)) {
    return (
      <section
        aria-labelledby="native-wireguard-import-title"
        className="space-y-3 border-t border-border pt-4"
      >
        <h2 className="text-xl font-bold" id="native-wireguard-import-title">
          {t("transports.nativeImport.title")}
        </h2>
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

  return <ProtectedNativeWireGuardImportCard requiredGuards={requiredGuards} />
}

/**
 * Raw text is scoped to `readFile` and parsed only in this browser. The parent
 * mounts this component only in authenticated HTTPS or in a short-lived local
 * connection proven by the server from socket, NDMS and route evidence; keys
 * never enter React state, storage, URLs, logs or errors.
 */
function ProtectedNativeWireGuardImportCard({
  requiredGuards = [],
}: {
  readonly requiredGuards?: readonly NdmsInterfaceInventoryResponseRequiredGuardsItem[]
}) {
  const { t, i18n } = useTranslation()
  const inputRef = useRef<HTMLInputElement>(null)
  const readGateRef = useRef(createNativeWireGuardFileReadGate())
  const [dragActive, setDragActive] = useState(false)
  const [state, setState] = useState<ImportState>({ status: "empty" })

  const clear = () => {
    readGateRef.current.invalidate()
    setState({ status: "empty" })
    if (inputRef.current) inputRef.current.value = ""
  }

  useEffect(
    () => () => {
      readGateRef.current.invalidate()
    },
    []
  )

  const readFile = async (file: File) => {
    const generation = readGateRef.current.begin()
    const fileIssue = validateNativeWireGuardImportFile(file)
    if (fileIssue) {
      if (readGateRef.current.isCurrent(generation)) {
        setState({ status: "error", fileName: file.name, code: fileIssue })
      }
      return
    }

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

    const textIssue = validateNativeWireGuardImportText(text)
    if (textIssue) {
      setState({ status: "error", fileName: file.name, code: textIssue })
      return
    }
    const preliminary = parseNativeWireGuardConfigPreview(text)
    if (!preliminary.ok) {
      setState({
        status: "error",
        fileName: file.name,
        code: preliminary.code,
        ...(preliminary.line ? { line: preliminary.line } : {}),
      })
      return
    }

    setState({
      status: "ready",
      fileName: file.name,
      fileSize: file.size,
      preview: preliminary.preview,
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
    chooseFiles(event.dataTransfer.files)
  }
  const openPicker = () => inputRef.current?.click()
  const onDropzoneKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault()
      openPicker()
    }
  }

  return (
    <section
      aria-labelledby="native-wireguard-import-title"
      className="space-y-3 border-t border-border pt-4"
    >
      <div className="space-y-1">
        <h2 className="text-xl font-bold" id="native-wireguard-import-title">
          {t("transports.nativeImport.title")}
        </h2>
        <p className="text-sm text-muted-foreground">
          {t("transports.nativeImport.description")}
        </p>
      </div>

      <input
        accept=".conf,text/plain"
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
            !event.currentTarget.contains(event.relatedTarget as Node | null)
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
            size: NATIVE_WIREGUARD_CONF_MAX_BYTES / 1024,
          })}
        </span>
      </div>

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
        </div>
      ) : null}

      <Alert variant="warning">
        <ShieldAlertIcon />
        <AlertTitle>
          {t("transports.nativeImport.applyBlockedTitle")}
        </AlertTitle>
        <AlertDescription className="space-y-2">
          <p>{t("transports.nativeImport.applyBlockedDescription")}</p>
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
      <div className="flex justify-end">
        <Button disabled title={t("transports.nativeImport.applyBlockedTitle")}>
          {t("transports.nativeImport.apply")}
        </Button>
      </div>
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
    case "conf-extension-required":
      return t(
        "transports.nativeImport.errors.conf-extension-required",
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
    case "malformed_line":
      return t("transports.nativeImport.errors.malformed_line", options)
    case "unknown_section":
      return t("transports.nativeImport.errors.unknown_section", options)
    case "duplicate_section":
      return t("transports.nativeImport.errors.duplicate_section", options)
    case "duplicate_field":
      return t("transports.nativeImport.errors.duplicate_field", options)
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

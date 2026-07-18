import { DownloadIcon, UploadIcon } from "lucide-react"
import { useRef } from "react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"

import type { ConfigObject } from "@/api/generated/model/configObject"
import type { RouteRule } from "@/api/generated/model/routeRule"
import { Button } from "@/components/ui/button"

type Props = {
  config?: ConfigObject
  disabled?: boolean
  kind: "lists" | "routing-rules"
  onImport: (config: ConfigObject) => void
}

export function ConfigTransferButtons({
  config,
  disabled,
  kind,
  onImport,
}: Props) {
  const { t } = useTranslation()
  const inputRef = useRef<HTMLInputElement>(null)

  const exportData = () => {
    if (!config) return
    const payload =
      kind === "lists"
        ? { format: "keen-pbr-sb", version: 1, kind, lists: config.lists ?? {} }
        : {
            format: "keen-pbr-sb",
            version: 1,
            kind,
            rules: config.route?.rules ?? [],
          }
    const blob = new Blob([JSON.stringify(payload, null, 2) + "\n"], {
      type: "application/json",
    })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement("a")
    anchor.href = url
    anchor.download = `keen-pbr-sb-${kind}-${new Date().toISOString().slice(0, 10)}.json`
    anchor.click()
    URL.revokeObjectURL(url)
  }

  const importData = async (file?: File) => {
    if (!file || !config) return
    try {
      const parsed = JSON.parse(await file.text()) as Record<string, unknown>
      if (parsed.format !== "keen-pbr-sb" || parsed.kind !== kind)
        throw new Error(t("configTransfer.invalidFormat"))
      if (kind === "lists") {
        if (
          !parsed.lists ||
          typeof parsed.lists !== "object" ||
          Array.isArray(parsed.lists)
        )
          throw new Error(t("configTransfer.invalidFormat"))
        const replace = window.confirm(t("configTransfer.replaceLists"))
        onImport({
          ...config,
          lists: replace
            ? (parsed.lists as ConfigObject["lists"])
            : {
                ...(config.lists ?? {}),
                ...(parsed.lists as ConfigObject["lists"]),
              },
        })
      } else {
        if (!Array.isArray(parsed.rules))
          throw new Error(t("configTransfer.invalidFormat"))
        const available = (config.outbounds ?? []).map((item) => item.tag)
        const imported = (parsed.rules as RouteRule[]).map((rule) => ({
          ...rule,
        }))
        for (const rule of imported) {
          if (!rule || typeof rule.outbound !== "string")
            throw new Error(t("configTransfer.invalidFormat"))
          if (!available.includes(rule.outbound)) {
            const replacement = window.prompt(
              t("configTransfer.mapOutbound", {
                missing: rule.outbound,
                available: available.join(", ") || "—",
              }),
              available[0] ?? ""
            )
            if (!replacement || !available.includes(replacement))
              throw new Error(t("configTransfer.outboundRequired"))
            rule.outbound = replacement
          }
        }
        const replace = window.confirm(t("configTransfer.replaceRules"))
        onImport({
          ...config,
          route: {
            ...config.route,
            rules: replace
              ? imported
              : [...(config.route?.rules ?? []), ...imported],
          },
        })
      }
    } catch (error) {
      toast.error(
        error instanceof Error
          ? error.message
          : t("configTransfer.invalidFormat"),
        { richColors: true }
      )
    } finally {
      if (inputRef.current) inputRef.current.value = ""
    }
  }

  return (
    <>
      <Button
        disabled={disabled || !config}
        onClick={exportData}
        variant="outline"
      >
        <DownloadIcon />
        {t("configTransfer.export")}
      </Button>
      <Button
        disabled={disabled || !config}
        onClick={() => inputRef.current?.click()}
        variant="outline"
      >
        <UploadIcon />
        {t("configTransfer.import")}
      </Button>
      <input
        accept="application/json,.json"
        className="hidden"
        onChange={(event) => void importData(event.target.files?.[0])}
        ref={inputRef}
        type="file"
      />
    </>
  )
}

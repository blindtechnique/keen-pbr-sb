import { DownloadIcon, UploadIcon } from "lucide-react"
import { useRef } from "react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"

import type { ConfigObject } from "@/api/generated/model/configObject"
import type { Outbound } from "@/api/generated/model/outbound"
import type { RouteRule } from "@/api/generated/model/routeRule"
import { Button } from "@/components/ui/button"
import { downloadJson, formatDownloadTimestamp } from "@/lib/download"

type Props = {
  config?: ConfigObject
  disabled?: boolean
  kind: "lists" | "routing-rules" | "outbounds"
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
    const payload = (() => {
      if (kind === "lists") {
        return {
          format: "keen-pbr-sb",
          version: 1,
          kind,
          lists: config.lists ?? {},
        }
      }
      if (kind === "outbounds") {
        return {
          format: "keen-pbr-sb",
          version: 1,
          kind,
          outbounds: config.outbounds ?? [],
        }
      }
      return {
        format: "keen-pbr-sb",
        version: 1,
        kind,
        rules: config.route?.rules ?? [],
      }
    })()
    downloadJson(
      `keen-pbr-sb-${kind}-${formatDownloadTimestamp()}.json`,
      payload
    )
  }

  const importData = async (file?: File) => {
    if (!file || !config) return
    try {
      const parsed = JSON.parse(await file.text()) as Record<string, unknown>
      if (
        parsed.format !== "keen-pbr-sb" ||
        parsed.version !== 1 ||
        parsed.kind !== kind
      )
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
      } else if (kind === "routing-rules") {
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
      } else {
        if (!Array.isArray(parsed.outbounds))
          throw new Error(t("configTransfer.invalidFormat"))
        const imported = parsed.outbounds as Outbound[]
        if (
          imported.some(
            (item) =>
              !item ||
              typeof item !== "object" ||
              typeof item.tag !== "string" ||
              typeof item.type !== "string"
          ) ||
          new Set(imported.map((item) => item.tag)).size !== imported.length
        ) {
          throw new Error(t("configTransfer.invalidFormat"))
        }

        const current = config.outbounds ?? []
        const currentTags = new Set(current.map((item) => item.tag))
        const conflicts = imported.filter((item) => currentTags.has(item.tag))
        const replaceConflicts =
          conflicts.length === 0 ||
          window.confirm(
            t("configTransfer.replaceOutboundConflicts", {
              tags: conflicts.map((item) => item.tag).join(", "),
            })
          )
        const importedByTag = new Map(imported.map((item) => [item.tag, item]))
        const merged = current.map((item) =>
          replaceConflicts ? (importedByTag.get(item.tag) ?? item) : item
        )
        const existingTags = new Set(merged.map((item) => item.tag))
        for (const item of imported) {
          if (!existingTags.has(item.tag)) merged.push(item)
        }
        onImport({ ...config, outbounds: merged })
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

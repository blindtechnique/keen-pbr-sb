import { useEffect, useRef, useState } from "react"
import { useTranslation } from "react-i18next"
import type { UpdateTransportOptions } from "@/api/generated/model"
import { Button } from "@/components/ui/button"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { OperationErrorMessage } from "@/components/shared/operation-error-message"
import { softwareUpdateResponseError } from "./software-update-view"
import { parseUpdateTransport } from "./software-update-transport"

export function UpdateTransportControl({
  disabled,
  saving,
  onSaving,
  onSaved,
}: {
  disabled: boolean
  saving: boolean
  onSaving: (value: boolean) => void
  onSaved: () => void
}) {
  const { t } = useTranslation()
  const [data, setData] = useState<UpdateTransportOptions | null>(null)
  const [draft, setDraft] = useState<string | null>(null)
  const [error, setError] = useState<unknown>(null)
  const [retry, setRetry] = useState(0)
  const discovery = useRef<AbortController | null>(null)
  useEffect(() => {
    const controller = new AbortController()
    discovery.current = controller
    void fetch("/api/system/update/transport", { signal: controller.signal })
      .then(async (response) => {
        const body = await response.json()
        if (!response.ok)
          throw softwareUpdateResponseError(response.status, body)
        const parsed = parseUpdateTransport(body)
        if (!controller.signal.aborted) {
          setData(parsed)
          setError(null)
        }
      })
      .catch((cause) => {
        if (!controller.signal.aborted) setError(cause)
      })
    return () => {
      controller.abort()
      if (discovery.current === controller) discovery.current = null
    }
  }, [retry])
  const selected = draft ?? data?.outbound ?? ""
  const save = async () => {
    if (!data || disabled || saving || selected === data.outbound) return
    // A slow retry may have read the old preference before this save.
    // Abort and ignore it so its response cannot replace the saved choice.
    discovery.current?.abort()
    onSaving(true)
    setError(null)
    try {
      const response = await fetch("/api/system/update/transport", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ outbound: selected }),
      })
      const body = await response.json().catch(() => ({}))
      if (!response.ok) throw softwareUpdateResponseError(response.status, body)
      if (body.outbound !== selected)
        throw new Error("Invalid update transport response")
      setData({ ...data, outbound: selected })
      setDraft(null)
      onSaved()
    } catch (cause) {
      setError(cause)
    } finally {
      onSaving(false)
    }
  }
  return (
    <div className="space-y-2">
      <Label htmlFor="software-update-transport">
        {t("pages.settings.softwareUpdate.downloadPath")}
      </Label>
      <div className="flex flex-wrap gap-2">
        <Select
          value={selected || "__router__"}
          disabled={disabled || saving || !data}
          onValueChange={(value) => {
            if (value != null) setDraft(value === "__router__" ? "" : value)
          }}
        >
          <SelectTrigger
            id="software-update-transport"
            aria-describedby={
              data?.options_available === false
                ? "software-update-transport-hint software-update-transport-warning"
                : "software-update-transport-hint"
            }
          >
            <SelectValue>
              {selected
                ? (data?.options.find((option) => option.tag === selected)
                    ?.name ?? selected)
                : t("pages.settings.softwareUpdate.routerPath")}
            </SelectValue>
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="__router__">
              {t("pages.settings.softwareUpdate.routerPath")}
            </SelectItem>
            {selected &&
              !data?.options.some((option) => option.tag === selected) && (
                <SelectItem value={selected} disabled>
                  {selected}
                </SelectItem>
              )}
            {data?.options.map((option) => (
              <SelectItem key={option.tag} value={option.tag}>
                {option.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Button
          variant="outline"
          disabled={disabled || saving || !data || selected === data.outbound}
          onClick={() => void save()}
        >
          {t("pages.settings.softwareUpdate.saveDownloadPath")}
        </Button>
      </div>
      <p
        id="software-update-transport-hint"
        className="text-sm text-muted-foreground"
      >
        {t("pages.settings.softwareUpdate.downloadPathHint")}
      </p>
      {data?.options_available === false && (
        <p
          id="software-update-transport-warning"
          role="status"
          className="text-sm text-warning"
        >
          {t("pages.settings.softwareUpdate.downloadChoicesUnavailable")}
        </p>
      )}
      {error != null && (
        <OperationErrorMessage
          error={error}
          fallbackSummary={t(
            "pages.settings.softwareUpdate.downloadPathFailed"
          )}
        />
      )}
      {(error != null || data?.options_available === false) && (
        <Button
          variant="outline"
          disabled={disabled || saving}
          onClick={() => setRetry((value) => value + 1)}
        >
          {t("common.retry")}
        </Button>
      )}
    </div>
  )
}

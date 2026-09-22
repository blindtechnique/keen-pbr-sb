import { useState } from "react"
import { useTranslation } from "react-i18next"
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

export function UpdateChannelControl({
  channel,
  disabled,
  saving,
  onSaving,
  onSaved,
}: {
  channel?: string
  disabled: boolean
  saving: boolean
  onSaving: (saving: boolean) => void
  onSaved: (channel: "stable" | "alpha") => void
}) {
  const { t } = useTranslation()
  const [draft, setDraft] = useState<"stable" | "alpha" | null>(null)
  const [error, setError] = useState<unknown>(null)
  const selected = draft ?? channel
  const save = async () => {
    if (disabled || saving || (selected !== "stable" && selected !== "alpha"))
      return
    onSaving(true)
    setError(null)
    try {
      const response = await fetch("/api/system/update/channel", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: selected }),
      })
      const body = await response.json().catch(() => ({}))
      if (!response.ok) throw softwareUpdateResponseError(response.status, body)
      if (body.channel !== selected)
        throw new Error(t("pages.settings.softwareUpdate.channelSaveFailed"))
      setDraft(null)
      onSaved(selected)
    } catch (cause) {
      setError(cause)
    } finally {
      onSaving(false)
    }
  }
  return (
    <div className="space-y-2">
      <Label htmlFor="software-update-channel">
        {t("pages.settings.softwareUpdate.channel")}
      </Label>
      <div className="flex flex-wrap gap-2">
        <Select
          value={selected ?? null}
          disabled={disabled || saving || !channel}
          onValueChange={(value) => {
            if (value === "stable" || value === "alpha") setDraft(value)
          }}
        >
          <SelectTrigger
            id="software-update-channel"
            aria-describedby="software-update-channel-hint"
          >
            <SelectValue>
              {selected === "alpha"
                ? t("pages.settings.softwareUpdate.alphaChannel")
                : selected === "stable"
                  ? t("pages.settings.softwareUpdate.stableChannel")
                  : "—"}
            </SelectValue>
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="stable">
              {t("pages.settings.softwareUpdate.stableChannel")}
            </SelectItem>
            <SelectItem value="alpha">
              {t("pages.settings.softwareUpdate.alphaChannel")}
            </SelectItem>
          </SelectContent>
        </Select>
        <Button
          variant="outline"
          disabled={disabled || saving || !draft || draft === channel}
          onClick={() => void save()}
        >
          {t("pages.settings.softwareUpdate.saveChannel")}
        </Button>
      </div>
      <p
        id="software-update-channel-hint"
        className="text-sm text-muted-foreground"
      >
        {t("pages.settings.softwareUpdate.channelHint")}
      </p>
      {selected === "alpha" && (
        <p className="text-sm text-warning">
          {t("pages.settings.softwareUpdate.alphaWarning")}
        </p>
      )}
      {error != null && (
        <OperationErrorMessage
          error={error}
          fallbackSummary={t("pages.settings.softwareUpdate.channelSaveFailed")}
        />
      )}
    </div>
  )
}

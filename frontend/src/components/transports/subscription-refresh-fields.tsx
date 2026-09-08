import { useId } from "react"
import { useTranslation } from "react-i18next"

import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  SUBSCRIPTION_REFRESH_PRESETS,
  subscriptionRefreshSeconds,
  type SubscriptionRefreshDraft,
} from "./subscription-settings-model"

export function SubscriptionRefreshFields({
  draft,
  onChange,
  originalSeconds,
  disabled,
}: {
  draft: SubscriptionRefreshDraft
  onChange: (draft: SubscriptionRefreshDraft) => void
  originalSeconds: number
  disabled: boolean
}) {
  const { t } = useTranslation()
  const id = useId()
  const intervals: number[] = [...SUBSCRIPTION_REFRESH_PRESETS]
  if (!intervals.includes(originalSeconds)) intervals.push(originalSeconds)
  const options = [
    ...intervals.map((seconds) => ({
      value: String(seconds),
      label:
        seconds === 0
          ? t("subscriptions.autoRefreshOff")
          : t("subscriptions.autoRefreshHours", { hours: seconds / 3_600 }),
    })),
    { value: "custom", label: t("subscriptions.autoRefreshCustom") },
  ]
  const invalid = subscriptionRefreshSeconds(draft) === undefined
  return (
    <div className="space-y-2">
      <label className="text-sm" htmlFor={`${id}-interval`}>
        {t("subscriptions.autoRefresh")}
      </label>
      <Select
        disabled={disabled}
        items={options}
        value={draft.interval}
        onValueChange={(interval) =>
          interval && onChange({ ...draft, interval })
        }
      >
        <SelectTrigger id={`${id}-interval`} aria-describedby={`${id}-hint`}>
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {options.map((option) => (
            <SelectItem key={option.value} value={option.value}>
              {option.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      {draft.interval === "custom" ? (
        <div className="space-y-1">
          <label className="text-sm" htmlFor={`${id}-hours`}>
            {t("subscriptions.autoRefreshCustomHours")}
          </label>
          <Input
            id={`${id}-hours`}
            type="number"
            min={1}
            max={168}
            step={1}
            required
            value={draft.customHours}
            disabled={disabled}
            aria-invalid={invalid || undefined}
            aria-describedby={invalid ? `${id}-error` : `${id}-hint`}
            onChange={(event) =>
              onChange({ ...draft, customHours: event.target.value })
            }
          />
          {invalid ? (
            <p
              className="text-sm text-destructive"
              id={`${id}-error`}
              role="alert"
            >
              {t("subscriptions.autoRefreshInvalid")}
            </p>
          ) : null}
        </div>
      ) : null}
      <p className="text-xs leading-5 text-muted-foreground" id={`${id}-hint`}>
        {t("subscriptions.autoRefreshHint")}
      </p>
    </div>
  )
}

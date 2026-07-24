import { useState } from "react"
import { useTranslation } from "react-i18next"

import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  buildCron,
  CUSTOM_SCHEDULE,
  parseSchedule,
  type Frequency,
  type ParsedSchedule,
} from "@/components/shared/schedule"

const HOURS = Array.from({ length: 24 }, (_, hour) => hour)

const WEEKDAY_KEYS = [
  "sunday",
  "monday",
  "tuesday",
  "wednesday",
  "thursday",
  "friday",
  "saturday",
] as const

/**
 * Cron is precise but unreadable. Offer the handful of schedules people
 * actually use and keep a raw field for anything more exotic.
 */
export function SchedulePicker({
  value,
  onChange,
}: {
  value: string
  onChange: (value: string) => void
}) {
  const { t } = useTranslation()
  const parsed = parseSchedule(value)
  const [selection, setSelection] = useState<{
    value: string
    frequency: Frequency
  }>({ value, frequency: parsed.frequency })
  const frequency =
    selection.value === value ? selection.frequency : parsed.frequency

  const update = (next: Partial<ParsedSchedule>) => {
    const merged = { ...parsed, frequency, ...next }
    if (merged.frequency === CUSTOM_SCHEDULE) {
      return
    }
    const nextValue = buildCron(merged)
    setSelection({ value: nextValue, frequency: merged.frequency })
    onChange(nextValue)
  }

  return (
    <div className="grid gap-2 sm:grid-cols-2">
      <Select
        onValueChange={(next) => {
          if (next === CUSTOM_SCHEDULE) {
            setSelection({ value, frequency: CUSTOM_SCHEDULE })
            return
          }
          update({ frequency: next as Frequency })
        }}
        value={frequency}
      >
        <SelectTrigger>
          <SelectValue>
            {(selected) =>
              t(
                `pages.settings.autoupdate.schedule.${
                  selected === CUSTOM_SCHEDULE ? "custom" : String(selected)
                }`
              )
            }
          </SelectValue>
        </SelectTrigger>
        <SelectContent>
          <SelectGroup>
            <SelectItem value="hourly">
              {t("pages.settings.autoupdate.schedule.hourly")}
            </SelectItem>
            <SelectItem value="daily">
              {t("pages.settings.autoupdate.schedule.daily")}
            </SelectItem>
            <SelectItem value="weekly">
              {t("pages.settings.autoupdate.schedule.weekly")}
            </SelectItem>
            <SelectItem value="monthly">
              {t("pages.settings.autoupdate.schedule.monthly")}
            </SelectItem>
            <SelectItem value={CUSTOM_SCHEDULE}>
              {t("pages.settings.autoupdate.schedule.custom")}
            </SelectItem>
          </SelectGroup>
        </SelectContent>
      </Select>

      {frequency === "weekly" ? (
        <Select
          onValueChange={(next) => update({ weekday: Number(next) })}
          value={String(parsed.weekday)}
        >
          <SelectTrigger>
            <SelectValue>
              {(selected) =>
                t(
                  `pages.settings.autoupdate.schedule.weekdays.${
                    WEEKDAY_KEYS[Number(selected)] ?? WEEKDAY_KEYS[0]
                  }`
                )
              }
            </SelectValue>
          </SelectTrigger>
          <SelectContent>
            <SelectGroup>
              {WEEKDAY_KEYS.map((key, index) => (
                <SelectItem key={key} value={String(index)}>
                  {t(`pages.settings.autoupdate.schedule.weekdays.${key}`)}
                </SelectItem>
              ))}
            </SelectGroup>
          </SelectContent>
        </Select>
      ) : null}

      {frequency === "monthly" ? (
        <Select
          onValueChange={(next) => update({ day: Number(next) })}
          value={String(parsed.day)}
        >
          <SelectTrigger>
            <SelectValue>
              {(selected) =>
                t("pages.settings.autoupdate.schedule.dayOfMonth", {
                  day: Number(selected),
                })
              }
            </SelectValue>
          </SelectTrigger>
          <SelectContent>
            <SelectGroup>
              {Array.from({ length: 28 }, (_, index) => index + 1).map((day) => (
                <SelectItem key={day} value={String(day)}>
                  {t("pages.settings.autoupdate.schedule.dayOfMonth", { day })}
                </SelectItem>
              ))}
            </SelectGroup>
          </SelectContent>
        </Select>
      ) : null}

      {frequency !== "hourly" && frequency !== CUSTOM_SCHEDULE ? (
        <Select
          onValueChange={(next) => update({ hour: Number(next) })}
          value={String(parsed.hour)}
        >
          <SelectTrigger>
            <SelectValue>
              {(selected) =>
                t("pages.settings.autoupdate.schedule.atHour", {
                  hour: String(Number(selected)).padStart(2, "0"),
                })
              }
            </SelectValue>
          </SelectTrigger>
          <SelectContent>
            <SelectGroup>
              {HOURS.map((hour) => (
                <SelectItem key={hour} value={String(hour)}>
                  {t("pages.settings.autoupdate.schedule.atHour", {
                    hour: String(hour).padStart(2, "0"),
                  })}
                </SelectItem>
              ))}
            </SelectGroup>
          </SelectContent>
        </Select>
      ) : null}

      {frequency === CUSTOM_SCHEDULE ? (
        <Input
          onChange={(event) => {
            const nextValue = event.target.value
            setSelection({ value: nextValue, frequency: CUSTOM_SCHEDULE })
            onChange(nextValue)
          }}
          placeholder="0 4 * * 0"
          value={value}
        />
      ) : null}
    </div>
  )
}

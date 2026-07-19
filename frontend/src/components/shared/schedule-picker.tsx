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

export const CUSTOM_SCHEDULE = "custom"

type Frequency = "hourly" | "daily" | "weekly" | "monthly" | typeof CUSTOM_SCHEDULE

type ParsedSchedule = {
  frequency: Frequency
  hour: number
  weekday: number
  day: number
}

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

  const update = (next: Partial<ParsedSchedule>) => {
    const merged = { ...parsed, ...next }
    if (merged.frequency === CUSTOM_SCHEDULE) {
      return
    }
    onChange(buildCron(merged))
  }

  return (
    <div className="grid gap-2 sm:grid-cols-2">
      <Select
        onValueChange={(next) => {
          if (next === CUSTOM_SCHEDULE) {
            onChange(value)
            update({ frequency: CUSTOM_SCHEDULE })
            return
          }
          update({ frequency: next as Frequency })
        }}
        value={parsed.frequency}
      >
        <SelectTrigger>
          <SelectValue />
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

      {parsed.frequency === "weekly" ? (
        <Select
          onValueChange={(next) => update({ weekday: Number(next) })}
          value={String(parsed.weekday)}
        >
          <SelectTrigger>
            <SelectValue />
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

      {parsed.frequency === "monthly" ? (
        <Select
          onValueChange={(next) => update({ day: Number(next) })}
          value={String(parsed.day)}
        >
          <SelectTrigger>
            <SelectValue />
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

      {parsed.frequency !== "hourly" && parsed.frequency !== CUSTOM_SCHEDULE ? (
        <Select
          onValueChange={(next) => update({ hour: Number(next) })}
          value={String(parsed.hour)}
        >
          <SelectTrigger>
            <SelectValue />
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

      {parsed.frequency === CUSTOM_SCHEDULE ? (
        <Input
          onChange={(event) => onChange(event.target.value)}
          placeholder="0 4 * * 0"
          value={value}
        />
      ) : null}
    </div>
  )
}

/** Recognises the expressions this picker can produce; anything else is custom. */
export function parseSchedule(expression: string): ParsedSchedule {
  const fallback: ParsedSchedule = {
    frequency: CUSTOM_SCHEDULE,
    hour: 4,
    weekday: 0,
    day: 1,
  }
  const fields = expression.trim().split(/\s+/)
  if (fields.length !== 5) {
    return fallback
  }

  const [minute, hour, dayOfMonth, month, weekday] = fields
  if (minute !== "0" || month !== "*") {
    return fallback
  }

  if (hour === "*" && dayOfMonth === "*" && weekday === "*") {
    return { ...fallback, frequency: "hourly" }
  }

  const parsedHour = Number(hour)
  if (!Number.isInteger(parsedHour) || parsedHour < 0 || parsedHour > 23) {
    return fallback
  }

  if (dayOfMonth === "*" && weekday === "*") {
    return { ...fallback, frequency: "daily", hour: parsedHour }
  }

  if (dayOfMonth === "*") {
    const parsedWeekday = Number(weekday)
    if (!Number.isInteger(parsedWeekday) || parsedWeekday < 0 || parsedWeekday > 6) {
      return fallback
    }
    return {
      ...fallback,
      frequency: "weekly",
      hour: parsedHour,
      weekday: parsedWeekday,
    }
  }

  if (weekday === "*") {
    const parsedDay = Number(dayOfMonth)
    if (!Number.isInteger(parsedDay) || parsedDay < 1 || parsedDay > 28) {
      return fallback
    }
    return {
      ...fallback,
      frequency: "monthly",
      hour: parsedHour,
      day: parsedDay,
    }
  }

  return fallback
}

function buildCron(schedule: ParsedSchedule): string {
  switch (schedule.frequency) {
    case "hourly":
      return "0 * * * *"
    case "daily":
      return `0 ${schedule.hour} * * *`
    case "weekly":
      return `0 ${schedule.hour} * * ${schedule.weekday}`
    case "monthly":
      return `0 ${schedule.hour} ${schedule.day} * *`
    default:
      return "0 4 * * 0"
  }
}

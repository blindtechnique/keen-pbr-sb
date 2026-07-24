export const CUSTOM_SCHEDULE = "custom"

export type Frequency =
  | "hourly"
  | "daily"
  | "weekly"
  | "monthly"
  | typeof CUSTOM_SCHEDULE

export type ParsedSchedule = {
  frequency: Frequency
  hour: number
  weekday: number
  day: number
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
    if (
      !Number.isInteger(parsedWeekday) ||
      parsedWeekday < 0 ||
      parsedWeekday > 6
    ) {
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

export function buildCron(schedule: ParsedSchedule): string {
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

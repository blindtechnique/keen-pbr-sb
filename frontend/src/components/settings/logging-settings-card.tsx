import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { useEffect, useState } from "react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"

type LogSettings = {
  file_enabled: boolean
  level: string
}

const LEVELS = ["error", "warn", "info", "verbose", "debug"] as const

/**
 * The log file is what makes a failure at boot investigable at all, so it is
 * on by default. The switch exists for people who would rather not have the
 * router write to flash continuously.
 */
export function LoggingSettingsCard() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()

  const query = useQuery<LogSettings>({
    queryKey: ["log-settings"],
    queryFn: async () => {
      const response = await fetch("/api/logs/settings")
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      return response.json()
    },
  })

  const [fileEnabled, setFileEnabled] = useState(true)
  const [level, setLevel] = useState("info")

  useEffect(() => {
    if (!query.data) return
    setFileEnabled(query.data.file_enabled)
    setLevel(query.data.level)
  }, [query.data])

  const saveMutation = useMutation({
    mutationFn: async () => {
      const response = await fetch("/api/logs/settings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ file_enabled: fileEnabled, level }),
      })
      const data = await response.json().catch(() => ({}))
      if (!response.ok || data.error) {
        throw new Error(data.error || `HTTP ${response.status}`)
      }
      return data
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["log-settings"] })
      toast.success(t("pages.settings.logging.saved"))
    },
    onError: (error: Error) => toast.error(error.message, { richColors: true }),
  })

  return (
    <Card size="sm">
      <CardHeader>
        <CardTitle>{t("pages.settings.logging.title")}</CardTitle>
        <CardDescription>
          {t("pages.settings.logging.description")}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-center gap-3">
          <Switch
            checked={fileEnabled}
            id="logging-enabled"
            onCheckedChange={setFileEnabled}
          />
          <Label className="cursor-pointer" htmlFor="logging-enabled">
            {t("pages.settings.logging.enabled")}
          </Label>
        </div>

        <div className="grid gap-1.5 sm:max-w-xs">
          <Label>{t("pages.settings.logging.level")}</Label>
          <Select
            disabled={!fileEnabled}
            onValueChange={(value) => setLevel(value ?? "info")}
            value={level}
          >
            <SelectTrigger>
              <SelectValue>
                {(selected) =>
                  t(`pages.settings.logging.levels.${String(selected)}`)
                }
              </SelectValue>
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                {LEVELS.map((value) => (
                  <SelectItem key={value} value={value}>
                    {t(`pages.settings.logging.levels.${value}`)}
                  </SelectItem>
                ))}
              </SelectGroup>
            </SelectContent>
          </Select>
          <p className="text-xs text-muted-foreground">
            {t("pages.settings.logging.levelHint")}
          </p>
        </div>

        <p className="text-xs text-muted-foreground">
          {t("pages.settings.logging.pathHint")}
        </p>

        <div className="flex justify-end">
          <Button
            disabled={saveMutation.isPending}
            onClick={() => saveMutation.mutate()}
          >
            {saveMutation.isPending
              ? t("common.saving")
              : t("pages.settings.logging.save")}
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import {
  forwardRef,
  useImperativeHandle,
  useState,
  type ForwardedRef,
} from "react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"

import { LogDiagnosticsTools } from "@/components/settings/log-diagnostics-tools"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
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
import type {
  SettingsSectionController,
  SettingsSectionState,
} from "@/components/settings/settings-section-control"

type LogSettings = {
  file_enabled: boolean
  level: string
}

type LogSettingsDraft = Partial<LogSettings>

const LEVELS = ["error", "warn", "info", "verbose", "debug"] as const

/**
 * The log file is what makes a failure at boot investigable at all, so it is
 * on by default. The switch exists for people who would rather not have the
 * router write to flash continuously.
 */
export const LoggingSettingsCard = forwardRef(LoggingSettingsCardInner)

function LoggingSettingsCardInner(
  {
    onStateChange,
  }: {
    onStateChange: (state: SettingsSectionState) => void
  },
  ref: ForwardedRef<SettingsSectionController>
) {
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

  const [draft, setDraft] = useState<LogSettingsDraft>({})
  const fileEnabled = draft.file_enabled ?? query.data?.file_enabled ?? true
  const level = draft.level ?? query.data?.level ?? "info"
  const getSectionState = (nextDraft = draft): SettingsSectionState => ({
    dirty: Object.keys(nextDraft).length > 0,
    valid: true,
  })
  const updateDraft = (patch: LogSettingsDraft) => {
    const nextDraft = { ...draft, ...patch }
    setDraft(nextDraft)
    onStateChange(getSectionState(nextDraft))
  }

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
      setDraft({})
      onStateChange({ dirty: false, valid: true })
      toast.success(t("pages.settings.logging.saved"))
    },
    onError: (error: Error) => toast.error(error.message, { richColors: true }),
  })

  useImperativeHandle(ref, () => ({
    reset: () => {
      setDraft({})
      onStateChange({ dirty: false, valid: true })
    },
    save: async () => {
      if (!getSectionState().dirty) {
        return
      }
      await saveMutation.mutateAsync()
    },
  }))

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
            onCheckedChange={(nextEnabled) =>
              updateDraft({ file_enabled: nextEnabled })
            }
          />
          <Label className="cursor-pointer" htmlFor="logging-enabled">
            {t("pages.settings.logging.enabled")}
          </Label>
        </div>

        <div className="grid gap-1.5 sm:max-w-xs">
          <Label>{t("pages.settings.logging.level")}</Label>
          <Select
            disabled={!fileEnabled}
            onValueChange={(value) => updateDraft({ level: value ?? "info" })}
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
        <LogDiagnosticsTools
          labels={{
            openLogAction: t("pages.settings.logging.viewer.open"),
            downloadDiagnosticsAction: t(
              "pages.settings.logging.diagnostics.download"
            ),
            downloadingDiagnosticsAction: t(
              "pages.settings.logging.diagnostics.downloading"
            ),
            logDialogTitle: t("pages.settings.logging.viewer.title"),
            logDialogDescription: t(
              "pages.settings.logging.viewer.description"
            ),
            logEditorAriaLabel: t("pages.settings.logging.viewer.ariaLabel"),
            refreshLogAction: t("pages.settings.logging.viewer.refresh"),
            refreshingLogAction: t("pages.settings.logging.viewer.refreshing"),
            closeAction: t("common.close"),
            logLoading: t("pages.settings.logging.viewer.loading"),
            logEmpty: t("pages.settings.logging.viewer.empty"),
            logLoadFailed: t("pages.settings.logging.viewer.failed"),
            diagnosticsDownloadFailed: t(
              "pages.settings.logging.diagnostics.failed"
            ),
            diagnosticsDialogTitle: t(
              "pages.settings.logging.diagnostics.title"
            ),
            diagnosticsDialogDescription: t(
              "pages.settings.logging.diagnostics.description"
            ),
            diagnosticsTrustWarning: t(
              "pages.settings.logging.diagnostics.trustWarning"
            ),
            diagnosticsIncludeLists: t(
              "pages.settings.logging.diagnostics.includeLists"
            ),
            diagnosticsConfirmAction: t(
              "pages.settings.logging.diagnostics.confirm"
            ),
          }}
        />
      </CardContent>
    </Card>
  )
}

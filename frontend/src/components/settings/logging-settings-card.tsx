import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import {
  forwardRef,
  useImperativeHandle,
  useState,
  type ForwardedRef,
} from "react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"
import type { LogSettingsRequest } from "@/api/generated/model"
import {
  DEFAULT_LOG_FILE_BYTES,
  DEFAULT_LOG_MAX_AGE_DAYS,
  LOG_SETTINGS_QUERY_KEY,
  loadLogSettings,
  logFileSizeChoices,
  logAgeChoices,
  logSizeUnit,
  saveLogSettings,
  updateLogSettingsDraft,
} from "@/lib/log-settings"

import { LogDiagnosticsTools } from "@/components/settings/log-diagnostics-tools"
import {
  Field,
  FieldContent,
  FieldHint,
  FieldLabel,
} from "@/components/shared/field"
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
import { Checkbox } from "@/components/ui/checkbox"
import type {
  SettingsSectionController,
  SettingsSectionState,
} from "@/components/settings/settings-section-control"

type LogSettingsDraft = LogSettingsRequest

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

  const query = useQuery({
    queryKey: LOG_SETTINGS_QUERY_KEY,
    queryFn: loadLogSettings,
  })

  const [draft, setDraft] = useState<LogSettingsDraft>({})
  const fileEnabled = draft.file_enabled ?? query.data?.file_enabled ?? true
  const level = draft.level ?? query.data?.level ?? "info"
  const maximumBytes =
    draft.max_file_bytes ?? query.data?.max_file_bytes ?? DEFAULT_LOG_FILE_BYTES
  const sizeEnabled =
    draft.size_limit_enabled ?? query.data?.size_limit_enabled ?? true
  const ageEnabled =
    draft.age_limit_enabled ?? query.data?.age_limit_enabled ?? false
  const maximumAge =
    draft.max_age_days ?? query.data?.max_age_days ?? DEFAULT_LOG_MAX_AGE_DAYS
  const sizeLabel = (bytes: number) => {
    const unit = logSizeUnit(bytes)
    return unit.key === "pages.settings.logging.sizeKiB"
      ? t("pages.settings.logging.sizeKiB", { size: unit.size })
      : t("pages.settings.logging.sizeMiB", { size: unit.size })
  }
  const getSectionState = (nextDraft = draft): SettingsSectionState => ({
    dirty: Object.keys(nextDraft).length > 0,
    valid: true,
  })
  const updateDraft = (patch: LogSettingsDraft) => {
    const nextDraft = updateLogSettingsDraft(draft, patch, {
      file_enabled: query.data?.file_enabled ?? true,
      level: query.data?.level ?? "info",
      max_file_bytes: query.data?.max_file_bytes ?? DEFAULT_LOG_FILE_BYTES,
      size_limit_enabled: query.data?.size_limit_enabled ?? true,
      age_limit_enabled: query.data?.age_limit_enabled ?? false,
      max_age_days: query.data?.max_age_days ?? DEFAULT_LOG_MAX_AGE_DAYS,
    })
    setDraft(nextDraft)
    onStateChange(getSectionState(nextDraft))
  }

  const saveMutation = useMutation({
    mutationFn: () => saveLogSettings(draft),
    onSuccess: (settings) => {
      queryClient.setQueryData(LOG_SETTINGS_QUERY_KEY, settings)
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
    <Card className="w-full min-w-0" size="sm">
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
            disabled={saveMutation.isPending}
            id="logging-enabled"
            onCheckedChange={(nextEnabled) =>
              updateDraft({ file_enabled: nextEnabled })
            }
          />
          <Label className="cursor-pointer" htmlFor="logging-enabled">
            {t("pages.settings.logging.enabled")}
          </Label>
        </div>

        <Field width="short">
          <FieldLabel htmlFor="logging-level">
            {t("pages.settings.logging.level")}
          </FieldLabel>
          <FieldContent>
            <Select
              disabled={!fileEnabled || saveMutation.isPending}
              onValueChange={(value) =>
                updateDraft({
                  level: (value ?? "info") as (typeof LEVELS)[number],
                })
              }
              value={level}
            >
              <SelectTrigger id="logging-level">
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
            <FieldHint description={t("pages.settings.logging.levelHint")} />
          </FieldContent>
        </Field>

        <div className="flex items-center gap-3">
          <Checkbox
            id="logging-size-enabled"
            checked={sizeEnabled}
            disabled={saveMutation.isPending}
            onCheckedChange={(checked) =>
              updateDraft({ size_limit_enabled: checked === true })
            }
          />
          <Label htmlFor="logging-size-enabled">
            {t("pages.settings.logging.sizeLimitEnabled")}
          </Label>
        </div>
        <Field width="short">
          <FieldLabel htmlFor="logging-max-bytes">
            {t("pages.settings.logging.maxFileBytes")}
          </FieldLabel>
          <FieldContent>
            <Select
              disabled={!sizeEnabled || saveMutation.isPending}
              onValueChange={(value) => {
                if (value !== null)
                  updateDraft({ max_file_bytes: Number(value) })
              }}
              value={String(maximumBytes)}
            >
              <SelectTrigger id="logging-max-bytes">
                <SelectValue>{() => sizeLabel(maximumBytes)}</SelectValue>
              </SelectTrigger>
              <SelectContent>
                {logFileSizeChoices(maximumBytes).map((value) => (
                  <SelectItem key={value} value={String(value)}>
                    {sizeLabel(value)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <FieldHint
              description={t("pages.settings.logging.maxFileBytesHint", {
                size: sizeLabel(maximumBytes),
                total: sizeLabel(maximumBytes * 2),
              })}
            />
          </FieldContent>
        </Field>

        <div className="flex items-center gap-3">
          <Checkbox
            id="logging-age-enabled"
            checked={ageEnabled}
            disabled={saveMutation.isPending}
            onCheckedChange={(checked) =>
              updateDraft({ age_limit_enabled: checked === true })
            }
          />
          <Label htmlFor="logging-age-enabled">
            {t("pages.settings.logging.ageLimitEnabled")}
          </Label>
        </div>
        <Field width="short">
          <FieldLabel htmlFor="logging-max-age">
            {t("pages.settings.logging.maxAgeDays")}
          </FieldLabel>
          <FieldContent>
            <Select
              disabled={!ageEnabled || saveMutation.isPending}
              value={String(maximumAge)}
              onValueChange={(value) => {
                if (value !== null) updateDraft({ max_age_days: Number(value) })
              }}
            >
              <SelectTrigger id="logging-max-age">
                <SelectValue>{() => String(maximumAge)}</SelectValue>
              </SelectTrigger>
              <SelectContent>
                {logAgeChoices(maximumAge).map((days) => (
                  <SelectItem key={days} value={String(days)}>
                    {days}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <FieldHint description={t("pages.settings.logging.ageHint")} />
          </FieldContent>
        </Field>
        {!sizeEnabled && !ageEnabled ? (
          <p className="text-xs text-muted-foreground">
            {t("pages.settings.logging.retentionDisabled")}
          </p>
        ) : null}

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

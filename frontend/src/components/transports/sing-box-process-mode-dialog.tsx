import { AlertTriangleIcon } from "lucide-react"
import { useTranslation } from "react-i18next"

import type { SingBoxProcessMode } from "@/api/transport-runtime-settings"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { cn } from "@/lib/utils"

const PROCESS_MODES: SingBoxProcessMode[] = ["isolated", "shared"]

export function SingBoxProcessModeDialog({
  currentMode,
  onModeChange,
  onOpenChange,
  onSubmit,
  open,
  pending,
  restartRequired,
  selectedMode,
}: {
  currentMode: SingBoxProcessMode
  onModeChange: (mode: SingBoxProcessMode) => void
  onOpenChange: (open: boolean) => void
  onSubmit: () => void
  open: boolean
  pending: boolean
  restartRequired: boolean
  selectedMode: SingBoxProcessMode
}) {
  const { t } = useTranslation()

  return (
    <Dialog onOpenChange={onOpenChange} open={open}>
      <DialogContent className="max-sm:top-auto max-sm:bottom-0 max-sm:left-0 max-sm:max-h-[calc(100dvh-0.75rem)] max-sm:max-w-none max-sm:translate-x-0 max-sm:translate-y-0 max-sm:rounded-b-none max-sm:border-x-0 max-sm:border-b-0 sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>{t("transports.processMode.title")}</DialogTitle>
          <DialogDescription>
            {t("transports.processMode.description")}
          </DialogDescription>
        </DialogHeader>

        <fieldset className="space-y-2.5">
          <legend className="sr-only">
            {t("transports.processMode.title")}
          </legend>
          {PROCESS_MODES.map((mode) => (
            <button
              aria-pressed={selectedMode === mode}
              className={cn(
                "flex w-full flex-col gap-1 rounded-[4px] border bg-background px-4 py-3 text-left transition-[border-color,background-color,box-shadow] hover:border-primary/60 hover:shadow-sm",
                selectedMode === mode &&
                  "border-primary bg-primary/8 shadow-[inset_0_0_0_1px_var(--color-primary)]"
              )}
              key={mode}
              onClick={() => onModeChange(mode)}
              type="button"
            >
              <span className="font-medium">
                {t(`transports.processMode.modes.${mode}.label`)}
              </span>
              <span className="text-sm text-muted-foreground">
                {t(`transports.processMode.modes.${mode}.description`)}
              </span>
            </button>
          ))}
        </fieldset>

        <Alert variant="warning">
          <AlertTriangleIcon />
          <AlertDescription>
            {t("transports.processMode.restartWarning")}
          </AlertDescription>
        </Alert>

        <DialogFooter className="max-sm:items-stretch">
          <Button
            disabled={pending}
            onClick={() => onOpenChange(false)}
            type="button"
            variant="outline"
          >
            {t("common.cancel")}
          </Button>
          <Button
            disabled={
              pending || (selectedMode === currentMode && !restartRequired)
            }
            onClick={onSubmit}
            type="button"
          >
            {pending
              ? t("transports.processMode.applying")
              : t("transports.processMode.apply")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

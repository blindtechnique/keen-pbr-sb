import {
  AlertCircle,
  CheckCircle2,
  Loader2,
  RefreshCw,
  SquareTerminal,
} from "lucide-react"
import { useEffect, useMemo, useState } from "react"
import { useTranslation } from "react-i18next"

import { type DnsCheckStatus, useDnsCheck } from "@/hooks/use-dns-check"
import { SectionCard } from "@/components/shared/section-card"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"

import { DnsCheckModal } from "./dns-check-modal"

export function DnsCheckWidget({
  dnsProbeEnabled,
  onStatusChange,
}: {
  dnsProbeEnabled: boolean
  onStatusChange?: (status: DnsCheckStatus) => void
}) {
  const { t } = useTranslation()
  const [showPcCheckDialog, setShowPcCheckDialog] = useState(false)
  const { status, startCheck, reset } = useDnsCheck()

  useEffect(() => {
    onStatusChange?.(status)
  }, [onStatusChange, status])

  useEffect(() => {
    if (!dnsProbeEnabled) {
      reset()
      return
    }

    startCheck(true)
  }, [dnsProbeEnabled, reset, startCheck])

  const isChecking = status === "checking"
  const isDisabled = !dnsProbeEnabled

  const cardClassName = useMemo(() => {
    if (isDisabled) {
      return "border-border bg-muted/20"
    }

    switch (status) {
      // Красным — только «проверили, и не сходится».
      case "browser-fail":
        return "border-destructive/40 bg-destructive/5"
      // А это «проверить не удалось»: поток событий не подключился, и о самом
      // DNS мы не узнали ничего. Красная карточка на дашборде читается как
      // «у тебя сломан DNS» — и человек идёт чинить то, что работает.
      case "sse-fail":
        return "border-warning/40 bg-warning/5"
      default:
        return undefined
    }
  }, [isDisabled, status])

  return (
    <>
      <SectionCard
        className={cardClassName}
        contentClassName="flex flex-1 flex-col"
        description={
          // Body text, not a caption: this line explains what the check does
          // and is the first thing read in the card.
          // The other cards start their content a card gap below the title.
          // This one is a description, which sits in the tighter header gap,
          // so it needs the difference added back to line up with them.
          <span className="mt-3.5 block text-foreground">
            {isDisabled
              ? t("overview.dnsCheck.card.disabledDescription")
              : t("overview.dnsCheck.card.description")}
          </span>
        }
        title={t("overview.dnsCheck.card.title")}
      >
        <div className="flex h-full flex-1 flex-col space-y-4">
          <div className="flex min-h-20 items-center rounded-lg border border-border/60 bg-background/60 px-4 py-3">
            <DnsStatusSummary disabled={isDisabled} status={status} />
          </div>

          <div className="mt-auto grid gap-2">
            <Button
              className="h-auto w-full justify-center text-center whitespace-normal"
              disabled={isChecking || isDisabled}
              onClick={() => {
                reset()
                startCheck(true)
              }}
              size="sm"
              variant="outline"
            >
              <RefreshCw className="h-4 w-4" />
              {isChecking
                ? t("overview.dnsCheck.card.checking")
                : t("overview.dnsCheck.card.runAgain")}
            </Button>
            <Button
              className="h-auto w-full justify-center text-center whitespace-normal"
              disabled={isDisabled}
              onClick={() => setShowPcCheckDialog(true)}
              size="sm"
              variant="outline"
            >
              <SquareTerminal className="h-4 w-4" />
              {t("overview.dnsCheck.card.testFromPc")}
            </Button>
          </div>
        </div>
      </SectionCard>

      <DnsCheckModal
        browserStatus={status}
        onOpenChange={setShowPcCheckDialog}
        open={showPcCheckDialog}
      />
    </>
  )
}

function DnsStatusSummary({
  disabled,
  status,
}: {
  disabled: boolean
  status: ReturnType<typeof useDnsCheck>["status"]
}) {
  const { t } = useTranslation()
  if (disabled) {
    return (
      <DnsStatusMessage
        icon={<AlertCircle className="h-5 w-5 text-muted-foreground" />}
        text={t("overview.dnsCheck.status.disabled")}
        tone="muted"
      />
    )
  }

  switch (status) {
    case "success":
      return (
        <DnsStatusMessage
          icon={<CheckCircle2 className="h-5 w-5 text-emerald-600" />}
          text={t("overview.dnsCheck.status.browserSuccess")}
          tone="success"
        />
      )
    case "pc-success":
      return (
        <DnsStatusMessage
          icon={<CheckCircle2 className="h-5 w-5 text-emerald-600" />}
          text={t("overview.dnsCheck.status.manualProbeSuccess")}
          tone="success"
        />
      )
    case "browser-fail":
      return (
        <DnsStatusMessage
          icon={<AlertCircle className="h-5 w-5 text-destructive" />}
          text={t("overview.dnsCheck.status.browserProbeFail")}
          tone="error"
        />
      )
    case "sse-fail":
      return (
        <DnsStatusMessage
          icon={<AlertCircle className="h-5 w-5 text-warning-foreground" />}
          text={t("overview.dnsCheck.status.sseUnavailable")}
          tone="warning"
        />
      )
    case "idle":
    case "checking":
      return (
        <div className="flex w-full items-center justify-center">
          <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
        </div>
      )
  }
}

function DnsStatusMessage({
  icon,
  text,
  tone,
}: {
  icon: React.ReactNode
  text: string
  tone: "success" | "error" | "warning" | "muted"
}) {
  return (
    <div
      className={cn(
        "flex w-full items-center gap-2",
        tone === "success" && "text-emerald-700 dark:text-emerald-300",
        tone === "error" && "text-destructive",
        // Не `text-warning`: в светлой теме это #e5952d, 2.42:1 на белом —
        // ниже порога 4.5:1. `--warning-foreground` = #9b5608, это 5.63:1; в
        // тёмной теме токен равен #ffbb57 и даёт 9.27:1, отдельного `dark:`
        // не нужно.
        tone === "warning" && "text-warning-foreground",
        tone === "muted" && "text-muted-foreground"
      )}
    >
      {icon}
      <span>{text}</span>
    </div>
  )
}

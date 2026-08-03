import { useState } from "react"
import {
  BugIcon,
  CheckIcon,
  ChevronDownIcon,
  LanguagesIcon,
  LoaderCircleIcon,
  LogOutIcon,
  MoreHorizontalIcon,
  PaletteIcon,
} from "lucide-react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"

import { NotificationsBell } from "@/components/layout/notifications-bell"
import { HeaderHealthIndicator } from "@/components/layout/header-health-indicator"
import { TOP_BAR_CONTROL_CLASS } from "@/components/layout/top-bar-control-styles"
import { useLanguage } from "@/components/language-provider"
import { useTheme } from "@/components/theme-provider"
import { Button } from "@/components/ui/button"
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover"
import { cn } from "@/lib/utils"

const THEME_OPTIONS = [
  { value: "system", labelKey: "theme.useSystem" },
  { value: "light", labelKey: "theme.light" },
  { value: "dark", labelKey: "theme.dark" },
] as const

const LANGUAGE_OPTIONS = [
  { value: "ru", label: "Русский" },
  { value: "en", label: "English" },
] as const

const ISSUES_URL = "https://github.com/blindtechnique/keen-pbr-sb/issues"

// Строка списка: высота и отступ пунктов меню, чтобы в шторке она читалась как
// продолжение навигации, а в меню шапки — как обычный пункт меню.
const CONTROL_ROW_CLASS =
  "h-12 w-full justify-start gap-3 rounded-none px-6 text-[14px] leading-6 font-normal text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground [&_svg:not([class*='size-'])]:size-5"

/**
 * Правая часть системной строки.
 *
 * Здесь было шесть иконок подряд, все без подписей. Состояние и уведомления
 * меняются сами и требуют внимания — им место на виду. Отчёт о проблеме, язык,
 * тема и выход сами не меняются и нужны редко; четыре постоянных места под них
 * — плохой размен. Они уехали под «⋯» теми же строками, что и в мобильной
 * шторке, так что список один и тот же на десктопе и на телефоне.
 */
export function TopBarControls() {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)

  return (
    <div className="flex items-center">
      <HeaderHealthIndicator />
      <NotificationsBell />
      <Popover onOpenChange={setOpen} open={open}>
        <PopoverTrigger
          render={
            <Button
              aria-label={t("common.moreControls")}
              className={TOP_BAR_CONTROL_CLASS}
              size="icon"
              title={t("common.moreControls")}
              variant="ghost"
            />
          }
        >
          <MoreHorizontalIcon />
        </PopoverTrigger>
        <PopoverContent align="end" className="w-72 p-0 py-1" side="bottom">
          <SystemControlRows onAfterAction={() => setOpen(false)} />
        </PopoverContent>
      </Popover>
    </div>
  )
}

/** Те же строки внизу мобильной шторки, без обёртки-меню. */
export function MobileMenuControls() {
  return (
    <div className="flex w-full flex-col py-1">
      <SystemControlRows />
    </div>
  )
}

function SystemControlRows({
  onAfterAction,
}: {
  /** Закрыть меню шапки после действия. В шторке закрывать нечего. */
  onAfterAction?: () => void
}) {
  const { t } = useTranslation()
  const { theme, setTheme } = useTheme()
  const { language, setLanguage } = useLanguage()
  // Варианты раскрываются прямо в списке, а не вторым всплывающим слоем.
  // Popover внутри Popover — лишний повод для промаха по «мимо меню», а выбор
  // из двух-трёх пунктов того не стоит.
  const [expanded, setExpanded] = useState<"language" | "theme" | null>(null)
  const [signingOut, setSigningOut] = useState(false)

  const handleSignOut = async () => {
    setSigningOut(true)
    try {
      const response = await fetch("/api/auth/logout", { method: "POST" })
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`)
      }
      window.location.assign("/")
    } catch {
      toast.error(t("auth.unavailable"), { richColors: true })
      setSigningOut(false)
    }
  }

  const languageLabel =
    LANGUAGE_OPTIONS.find((option) => option.value === language)?.label ??
    language
  const themeOption = THEME_OPTIONS.find((option) => option.value === theme)

  const toggle = (section: "language" | "theme") =>
    setExpanded((current) => (current === section ? null : section))

  return (
    <div className="flex flex-col">
      <Button
        className={CONTROL_ROW_CLASS}
        render={
          <a href={ISSUES_URL} rel="noopener noreferrer" target="_blank" />
        }
        variant="ghost"
      >
        <BugIcon />
        <span className="flex-1 text-left">{t("common.reportIssue")}</span>
      </Button>

      <ExpandableRow
        expanded={expanded === "language"}
        icon={<LanguagesIcon />}
        label={t("common.language")}
        onToggle={() => toggle("language")}
        value={languageLabel}
      >
        {LANGUAGE_OPTIONS.map((option) => (
          <OptionRow
            key={option.value}
            onSelect={() => {
              setLanguage(option.value)
              setExpanded(null)
              onAfterAction?.()
            }}
            selected={language === option.value}
          >
            {option.label}
          </OptionRow>
        ))}
      </ExpandableRow>

      <ExpandableRow
        expanded={expanded === "theme"}
        icon={<PaletteIcon />}
        label={t("common.theme")}
        onToggle={() => toggle("theme")}
        value={themeOption ? t(themeOption.labelKey) : undefined}
      >
        {THEME_OPTIONS.map((option) => (
          <OptionRow
            key={option.value}
            onSelect={() => {
              setTheme(option.value)
              setExpanded(null)
              onAfterAction?.()
            }}
            selected={theme === option.value}
          >
            {t(option.labelKey)}
          </OptionRow>
        ))}
      </ExpandableRow>

      <div aria-hidden="true" className="my-1 h-px bg-border" />

      <Button
        className={CONTROL_ROW_CLASS}
        disabled={signingOut}
        onClick={() => void handleSignOut()}
        variant="ghost"
      >
        {signingOut ? (
          <LoaderCircleIcon className="animate-spin" />
        ) : (
          <LogOutIcon />
        )}
        <span className="flex-1 text-left">{t("auth.signOut")}</span>
      </Button>
    </div>
  )
}

function ExpandableRow({
  children,
  expanded,
  icon,
  label,
  onToggle,
  value,
}: {
  children: React.ReactNode
  expanded: boolean
  icon: React.ReactNode
  label: string
  onToggle: () => void
  /** Текущее значение справа: иначе язык и тему видно только после раскрытия. */
  value?: string
}) {
  return (
    <>
      <Button
        aria-expanded={expanded}
        className={CONTROL_ROW_CLASS}
        onClick={onToggle}
        variant="ghost"
      >
        {icon}
        <span className="flex-1 text-left">{label}</span>
        {value ? <span className="text-muted-foreground">{value}</span> : null}
        <ChevronDownIcon
          aria-hidden="true"
          className={cn(
            "size-4 text-muted-foreground transition-transform",
            expanded && "rotate-180"
          )}
        />
      </Button>
      {expanded ? (
        <div aria-label={label} role="radiogroup">
          {children}
        </div>
      ) : null}
    </>
  )
}

function OptionRow({
  children,
  onSelect,
  selected,
}: {
  children: React.ReactNode
  onSelect: () => void
  selected: boolean
}) {
  return (
    <button
      aria-checked={selected}
      className={cn(
        "flex h-10 w-full items-center gap-3 pr-6 pl-14 text-left text-[14px] leading-6 hover:bg-sidebar-accent focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none",
        selected ? "font-medium text-foreground" : "text-muted-foreground"
      )}
      onClick={onSelect}
      role="radio"
      type="button"
    >
      <span className="flex-1">{children}</span>
      {selected ? <CheckIcon className="size-4 text-primary" /> : null}
    </button>
  )
}

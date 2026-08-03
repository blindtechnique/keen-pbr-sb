import { useState } from "react"
import {
  BugIcon,
  LanguagesIcon,
  LoaderCircleIcon,
  LogOutIcon,
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

// Строка шторки: высота и отступ пунктов меню над ней, чтобы список читался
// как продолжение навигации, а не как приклеенная снизу панель.
const SYSTEM_CONTROL_ROW_CLASS =
  "h-12 w-full justify-start gap-3 rounded-none px-6 text-[14px] leading-6 font-normal text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground [&_svg:not([class*='size-'])]:size-5"

/**
 * Compact theme and language pickers for the system bar, where KeeneticOS keeps
 * its own global controls.
 */
export function TopBarControls() {
  return <SystemControlIcons showNotifications={true} />
}

/**
 * Те же элементы в мобильной шторке, но строками с подписями.
 *
 * Иконки без подписей стояли рядом внизу шторки — прямо под списком разделов,
 * где у каждой строки есть название. Что делает «палитра» и чем «жучок»
 * отличается от «выхода», приходилось угадывать по картинке. Строки той же
 * высоты и с тем же отступом, что и пункты меню над ними, а у языка и темы
 * видно текущее значение: раньше его нужно было открыть, чтобы узнать.
 */
export function MobileMenuControls() {
  return (
    <div className="flex w-full flex-col py-1">
      <SystemControlIcons
        layout="list"
        popoverSide="top"
        showNotifications={false}
      />
    </div>
  )
}

function SystemControlIcons({
  layout = "bar",
  popoverSide = "bottom",
  showNotifications,
}: {
  layout?: "bar" | "list"
  popoverSide?: "top" | "bottom"
  showNotifications: boolean
}) {
  const { t } = useTranslation()
  const { theme, setTheme } = useTheme()
  const { language, setLanguage } = useLanguage()
  const [openMenu, setOpenMenu] = useState<"language" | "theme" | null>(null)
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

  const asList = layout === "list"
  const languageLabel =
    LANGUAGE_OPTIONS.find((option) => option.value === language)?.label ??
    language
  const themeOption = THEME_OPTIONS.find((option) => option.value === theme)

  return (
    <div className={cn(asList ? "flex flex-col" : "flex items-center")}>
      {showNotifications ? (
        <>
          <HeaderHealthIndicator />
          <NotificationsBell />
        </>
      ) : null}

      <Button
        aria-label={asList ? undefined : t("common.reportIssue")}
        className={asList ? SYSTEM_CONTROL_ROW_CLASS : TOP_BAR_CONTROL_CLASS}
        render={
          <a href={ISSUES_URL} rel="noopener noreferrer" target="_blank" />
        }
        size={asList ? "default" : "icon"}
        title={asList ? undefined : t("common.reportIssue")}
        variant="ghost"
      >
        <BugIcon />
        {asList ? (
          <span className="flex-1">{t("common.reportIssue")}</span>
        ) : null}
      </Button>

      <IconMenu
        asList={asList}
        icon={<LanguagesIcon />}
        label={t("common.language")}
        onOpenChange={(open) => setOpenMenu(open ? "language" : null)}
        open={openMenu === "language"}
        side={popoverSide}
        value={languageLabel}
      >
        {LANGUAGE_OPTIONS.map((option) => (
          <MenuOption
            active={language === option.value}
            key={option.value}
            onSelect={() => {
              setLanguage(option.value)
              setOpenMenu(null)
            }}
          >
            {option.label}
          </MenuOption>
        ))}
      </IconMenu>

      <IconMenu
        asList={asList}
        icon={<PaletteIcon />}
        label={t("common.theme")}
        onOpenChange={(open) => setOpenMenu(open ? "theme" : null)}
        open={openMenu === "theme"}
        side={popoverSide}
        value={themeOption ? t(themeOption.labelKey) : undefined}
      >
        {THEME_OPTIONS.map((option) => (
          <MenuOption
            active={theme === option.value}
            key={option.value}
            onSelect={() => {
              setTheme(option.value)
              setOpenMenu(null)
            }}
          >
            {t(option.labelKey)}
          </MenuOption>
        ))}
      </IconMenu>

      <Button
        aria-label={asList ? undefined : t("auth.signOut")}
        className={asList ? SYSTEM_CONTROL_ROW_CLASS : TOP_BAR_CONTROL_CLASS}
        disabled={signingOut}
        onClick={() => void handleSignOut()}
        size={asList ? "default" : "icon"}
        title={asList ? undefined : t("auth.signOut")}
        variant="ghost"
      >
        {signingOut ? (
          <LoaderCircleIcon className="animate-spin" />
        ) : (
          <LogOutIcon />
        )}
        {asList ? <span className="flex-1">{t("auth.signOut")}</span> : null}
      </Button>
    </div>
  )
}

function IconMenu({
  asList = false,
  icon,
  label,
  open,
  onOpenChange,
  side,
  value,
  children,
}: {
  asList?: boolean
  icon: React.ReactNode
  label: string
  open: boolean
  onOpenChange: (open: boolean) => void
  side: "top" | "bottom"
  /** Текущее значение справа в строке: язык и тема иначе не видны до открытия. */
  value?: string
  children: React.ReactNode
}) {
  return (
    <Popover onOpenChange={onOpenChange} open={open}>
      <PopoverTrigger
        render={
          <Button
            aria-label={asList ? undefined : label}
            className={
              asList ? SYSTEM_CONTROL_ROW_CLASS : TOP_BAR_CONTROL_CLASS
            }
            size={asList ? "default" : "icon"}
            title={asList ? undefined : label}
            variant="ghost"
          />
        }
      >
        {icon}
        {asList ? (
          <>
            <span className="flex-1">{label}</span>
            {value ? (
              <span className="text-muted-foreground">{value}</span>
            ) : null}
          </>
        ) : null}
      </PopoverTrigger>
      <PopoverContent
        align={asList ? "start" : "end"}
        className="w-44 p-1"
        side={side}
      >
        {children}
      </PopoverContent>
    </Popover>
  )
}

function MenuOption({
  active,
  onSelect,
  children,
}: {
  active: boolean
  onSelect: () => void
  children: React.ReactNode
}) {
  return (
    <button
      className={cn(
        "flex w-full items-center rounded-sm px-2 py-1.5 text-left text-sm hover:bg-accent",
        active && "font-medium text-primary"
      )}
      onClick={onSelect}
      type="button"
    >
      {children}
    </button>
  )
}

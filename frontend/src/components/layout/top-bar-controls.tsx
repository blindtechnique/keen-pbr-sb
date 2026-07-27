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

/**
 * Compact theme and language pickers for the system bar, where KeeneticOS keeps
 * its own global controls.
 */
export function TopBarControls() {
  return <SystemControlIcons showNotifications={true} />
}

export function MobileMenuControls() {
  return (
    <div className="flex h-16 w-full items-center justify-end gap-1 px-4">
      <SystemControlIcons popoverSide="top" showNotifications={false} />
    </div>
  )
}

function SystemControlIcons({
  popoverSide = "bottom",
  showNotifications,
}: {
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

  return (
    <div className="flex items-center">
      {showNotifications ? (
        <>
          <HeaderHealthIndicator />
          <NotificationsBell />
        </>
      ) : null}

      <Button
        aria-label={t("common.reportIssue")}
        className={TOP_BAR_CONTROL_CLASS}
        render={
          <a
            href={ISSUES_URL}
            rel="noopener noreferrer"
            target="_blank"
          />
        }
        size="icon"
        title={t("common.reportIssue")}
        variant="ghost"
      >
        <BugIcon />
      </Button>

      <IconMenu
        icon={<LanguagesIcon />}
        label={t("common.language")}
        onOpenChange={(open) => setOpenMenu(open ? "language" : null)}
        open={openMenu === "language"}
        side={popoverSide}
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
        icon={<PaletteIcon />}
        label={t("common.theme")}
        onOpenChange={(open) => setOpenMenu(open ? "theme" : null)}
        open={openMenu === "theme"}
        side={popoverSide}
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
        aria-label={t("auth.signOut")}
        className={TOP_BAR_CONTROL_CLASS}
        disabled={signingOut}
        onClick={() => void handleSignOut()}
        size="icon"
        title={t("auth.signOut")}
        variant="ghost"
      >
        {signingOut ? (
          <LoaderCircleIcon className="animate-spin" />
        ) : (
          <LogOutIcon />
        )}
      </Button>
    </div>
  )
}

function IconMenu({
  icon,
  label,
  open,
  onOpenChange,
  side,
  children,
}: {
  icon: React.ReactNode
  label: string
  open: boolean
  onOpenChange: (open: boolean) => void
  side: "top" | "bottom"
  children: React.ReactNode
}) {
  return (
    <Popover onOpenChange={onOpenChange} open={open}>
      <PopoverTrigger
        render={
          <Button
            aria-label={label}
            className={TOP_BAR_CONTROL_CLASS}
            size="icon"
            title={label}
            variant="ghost"
          />
        }
      >
        {icon}
      </PopoverTrigger>
      <PopoverContent align="end" className="w-44 p-1" side={side}>
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

import { useState } from "react"
import { LanguagesIcon, PaletteIcon } from "lucide-react"
import { useTranslation } from "react-i18next"

import { NotificationsBell } from "@/components/layout/notifications-bell"
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

/**
 * Compact theme and language pickers for the system bar, where KeeneticOS keeps
 * its own global controls.
 */
export function TopBarControls() {
  const { t } = useTranslation()
  const { theme, setTheme } = useTheme()
  const { language, setLanguage } = useLanguage()
  const [openMenu, setOpenMenu] = useState<"language" | "theme" | null>(null)

  return (
    <div className="flex items-center gap-0.5">
      <NotificationsBell />

      <IconMenu
        icon={<LanguagesIcon className="size-4" />}
        label={t("common.language")}
        onOpenChange={(open) => setOpenMenu(open ? "language" : null)}
        open={openMenu === "language"}
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
        icon={<PaletteIcon className="size-4" />}
        label={t("common.theme")}
        onOpenChange={(open) => setOpenMenu(open ? "theme" : null)}
        open={openMenu === "theme"}
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
    </div>
  )
}

function IconMenu({
  icon,
  label,
  open,
  onOpenChange,
  children,
}: {
  icon: React.ReactNode
  label: string
  open: boolean
  onOpenChange: (open: boolean) => void
  children: React.ReactNode
}) {
  return (
    <Popover onOpenChange={onOpenChange} open={open}>
      <PopoverTrigger
        render={
          <Button
            aria-label={label}
            className="size-9 text-primary hover:bg-accent hover:text-primary"
            size="icon"
            title={label}
            variant="ghost"
          />
        }
      >
        {icon}
      </PopoverTrigger>
      <PopoverContent align="end" className="w-44 p-1">
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

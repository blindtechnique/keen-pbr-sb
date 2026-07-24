import { useTranslation } from "react-i18next"

import { AppBrandHeader } from "@/components/layout/app-brand-header"
import {
  KeeneticCloseIcon,
  KeeneticMenuIcon,
} from "@/components/layout/keenetic-menu-icons"
import { HeaderHealthIndicator } from "@/components/layout/header-health-indicator"
import { NotificationsBell } from "@/components/layout/notifications-bell"
import { cn } from "@/lib/utils"

export function MobileAppHeader({
  className,
  menuOpen = false,
  onMenuClick,
}: {
  className?: string
  menuOpen?: boolean
  onMenuClick: () => void
}) {
  const { t } = useTranslation()
  const label = menuOpen ? t("brand.closeMenu") : t("brand.openMenu")

  return (
    <div
      className={cn(
        "keen-header-shadow keen-mobile-header relative flex h-16 w-full shrink-0 items-center bg-card pl-16",
        className
      )}
    >
      <button
        aria-expanded={menuOpen}
        aria-label={label}
        className={cn(
          "keen-mobile-menu-button absolute top-0 left-0 grid h-16 w-16 place-items-center",
          menuOpen
            ? "bg-primary text-primary-foreground"
            : "bg-sidebar text-[#686868] dark:text-[#c2c2c2]"
        )}
        onClick={onMenuClick}
        title={label}
        type="button"
      >
        <span className="grid size-6 place-items-center" aria-hidden="true">
          <KeeneticMenuIcon
            className={cn(
              "col-start-1 row-start-1 size-6 transition-opacity duration-75",
              menuOpen ? "opacity-0" : "opacity-100"
            )}
          />
          <KeeneticCloseIcon
            className={cn(
              "col-start-1 row-start-1 size-5 transition-opacity duration-75",
              menuOpen ? "opacity-100" : "opacity-0"
            )}
          />
        </span>
      </button>
      <AppBrandHeader className="min-w-0 flex-1 px-3" />
      <div className="flex shrink-0 items-center pr-2">
        <HeaderHealthIndicator />
        <NotificationsBell />
      </div>
    </div>
  )
}

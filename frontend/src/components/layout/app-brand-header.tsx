import { MenuIcon } from "lucide-react"
import { useTranslation } from "react-i18next"

import logoUrl from "@/assets/logo.png"
import { IconButtonWithTooltip } from "@/components/shared/icon-button-with-tooltip"
import { cn } from "@/lib/utils"

export function AppBrandHeader({
  onMenuClick,
  className = "",
}: {
  onMenuClick?: () => void
  variant?: "sidebar" | "topbar"
  className?: string
}) {
  const { t } = useTranslation()

  return (
    <div className={cn("flex items-center gap-3 px-0 py-0", className)}>
      {onMenuClick ? (
        <IconButtonWithTooltip
          className="size-9 shrink-0 rounded-lg border bg-card text-foreground shadow-none hover:bg-accent"
          label={t("brand.openMenu")}
          onClick={onMenuClick}
          size="icon"
          variant="ghost"
        >
          <MenuIcon className="h-4 w-4" />
        </IconButtonWithTooltip>
      ) : null}
      <a
        className="flex min-w-0 flex-1 items-center gap-3 rounded-md outline-none focus-visible:ring-2 focus-visible:ring-ring"
        href="/"
        title={t("nav.items.systemMonitor")}
      >
        <img
          alt={t("brand.logoAlt")}
          className="size-9 shrink-0 rounded-md object-contain"
          src={logoUrl}
        />
        <span className="flex min-w-0 items-baseline gap-1.5 text-left group-data-[collapsible=icon]:hidden">
          <span className="truncate text-[19px] leading-6 font-medium tracking-[0.01em] text-primary">
            keen-pbr
          </span>
          <span className="truncate text-[19px] leading-6 font-light tracking-[0.08em] text-foreground/80 uppercase">
            sb
          </span>
        </span>
      </a>
    </div>
  )
}

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
      <div className="flex size-11 shrink-0 items-center justify-center overflow-hidden rounded-lg border border-primary/25 bg-primary shadow-sm ring-1 ring-primary/10">
        <img
          alt={t("brand.logoAlt")}
          className="size-full object-contain"
          src={logoUrl}
        />
      </div>
      <div className="grid min-w-0 flex-1 text-left leading-tight group-data-[collapsible=icon]:hidden">
        <span className="truncate text-base font-semibold tracking-[-0.01em]">keen-pbr-sb</span>
        <span className="truncate text-xs text-muted-foreground">
          {t("brand.tagline")}
        </span>
      </div>
    </div>
  )
}

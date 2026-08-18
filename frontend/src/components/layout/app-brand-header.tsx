import { useTranslation } from "react-i18next"

import logoUrl from "@/assets/logo.png"
import { cn } from "@/lib/utils"

export function AppBrandHeader({ className = "" }: { className?: string }) {
  const { t } = useTranslation()

  return (
    <div className={cn("flex items-center gap-3 px-0 py-0", className)}>
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
        {/* Lifted a hair off centre: the version underneath would otherwise
            drag the pair visually low against the logo. */}
        <span className="-mt-0.5 flex min-w-0 flex-col text-left">
          <span
            className="flex w-fit origin-left items-baseline leading-6"
            style={{ transform: "scaleX(1.08) scaleY(0.9)" }}
          >
            <span className="truncate text-[18px] font-medium tracking-[0.055em] text-primary">
              KEEN-PBR
            </span>
            <span className="truncate text-[18px] font-medium tracking-[0.055em] text-foreground">
              -SB
            </span>
          </span>
          {__APP_VERSION__ ? (
            <span className="truncate text-[11px] leading-[14px] tracking-[0.035em] text-muted-foreground">
              {__APP_VERSION__}
            </span>
          ) : null}
        </span>
      </a>
    </div>
  )
}

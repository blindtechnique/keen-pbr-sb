import type { ReactNode } from "react"
import { useLocation } from "wouter"

import { AppSidebar } from "@/components/app-sidebar"
import { AppBrandHeader } from "@/components/layout/app-brand-header"
import { useWarningBannerState } from "@/components/layout/warning-banner-state"
import { WarningBanner } from "@/components/layout/warning-banner"
import { TopBarControls } from "@/components/layout/top-bar-controls"
import { SidebarInset, SidebarProvider } from "@/components/ui/sidebar"
import { useSidebar } from "@/components/ui/sidebar-context"
import { cn } from "@/lib/utils"

export function AppShell({ children }: { children: ReactNode }) {
  const warningBannerState = useWarningBannerState()
  const [location] = useLocation()
  // KeeneticOS tints only the dashboard, where cards sit on a grey canvas.
  // Every other section is a plain white page.
  const isOverview = location === "/"

  return (
    <SidebarProvider defaultOpen={true}>
      <div
        className={cn(
          "flex min-h-screen w-full max-w-full overflow-x-clip",
          isOverview ? "bg-background" : "bg-card"
        )}
      >
        <a
          className="sr-only z-50 rounded-md bg-background px-3 py-2 text-sm font-medium shadow focus:not-sr-only focus:fixed focus:top-3 focus:left-3"
          href="#main-content"
        >
          Skip to content
        </a>
        <AppSidebar />
        <SidebarInset className="max-w-full min-w-0 overflow-x-clip bg-transparent">
          <MobileSidebarHeader />
          <DesktopSystemBar />
          <WarningBanner state={warningBannerState} />
          <main
            aria-labelledby="page-title"
            className="min-w-0 flex-1"
            id="main-content"
          >
            <div
              className="mx-auto max-w-[92rem] min-w-0 px-4 py-4 sm:px-6 lg:px-8 lg:py-5"
            >
              {children}
            </div>
          </main>
        </SidebarInset>
      </div>
    </SidebarProvider>
  )
}

function DesktopSystemBar() {
  return (
    <div className="sticky top-0 z-20 hidden h-16 items-center justify-between bg-card px-8 md:flex">
      <div className="flex items-center gap-3">
        <span className="size-2.5 rounded-full bg-success shadow-[0_0_0_4px_color-mix(in_srgb,var(--success)_14%,transparent)]" />
        <span className="text-[15px] font-medium text-primary">keen-pbr</span>
        <span className="text-[15px] font-light tracking-[0.08em] text-foreground/80 uppercase">
          sb
        </span>
        <span className="ml-2 text-[13px] text-muted-foreground">
          Keenetic / Netcraze
        </span>
      </div>
      <TopBarControls />
    </div>
  )
}

function MobileSidebarHeader() {
  const { toggleSidebar } = useSidebar()

  return (
    <div className="sticky top-0 z-30 bg-card md:hidden">
      <div className="flex items-center gap-2 px-4 py-2.5">
        <AppBrandHeader
          className="min-w-0 flex-1"
          onMenuClick={toggleSidebar}
          variant="topbar"
        />
        <TopBarControls />
      </div>
    </div>
  )
}

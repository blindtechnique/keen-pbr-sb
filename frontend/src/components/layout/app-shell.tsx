import type { ReactNode } from "react"

import { AppSidebar } from "@/components/app-sidebar"
import { AppBrandHeader } from "@/components/layout/app-brand-header"
import { useWarningBannerState } from "@/components/layout/warning-banner-state"
import { WarningBanner } from "@/components/layout/warning-banner"
import {
  SidebarInset,
  SidebarProvider,
  SidebarTrigger,
} from "@/components/ui/sidebar"
import { useSidebar } from "@/components/ui/sidebar-context"
import { cn } from "@/lib/utils"

export function AppShell({ children }: { children: ReactNode }) {
  const warningBannerState = useWarningBannerState()

  return (
    <SidebarProvider defaultOpen={true}>
      <div className="flex min-h-screen w-full max-w-full overflow-x-clip bg-background">
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
          <main
            aria-labelledby="page-title"
            className="min-w-0 flex-1"
            id="main-content"
          >
            <div
              className={cn(
                "mx-auto max-w-[92rem] min-w-0 px-4 py-5 sm:px-6 lg:px-8 lg:py-7",
                warningBannerState.isVisible ? "pb-44 md:pb-48" : null
              )}
            >
              {children}
            </div>
          </main>
          <WarningBanner state={warningBannerState} />
        </SidebarInset>
      </div>
    </SidebarProvider>
  )
}

function DesktopSystemBar() {
  return (
    <div className="sticky top-0 z-20 hidden h-16 items-center justify-between border-b bg-card/95 px-8 backdrop-blur-md md:flex">
      <div className="flex items-center gap-3">
        <SidebarTrigger className="mr-1 border border-border bg-card text-primary" />
        <span className="size-2.5 rounded-full bg-success shadow-[0_0_0_4px_color-mix(in_srgb,var(--success)_14%,transparent)]" />
        <span className="text-sm font-semibold">keen-pbr-sb</span>
        <span className="text-sm text-muted-foreground">Keenetic / Netcraze</span>
      </div>
      <span className="rounded-full border border-primary/20 bg-accent px-3 py-1 text-xs font-semibold text-accent-foreground">
        Entware
      </span>
    </div>
  )
}

function MobileSidebarHeader() {
  const { toggleSidebar } = useSidebar()

  return (
    <div className="sticky top-0 z-30 bg-card/95 shadow-sm backdrop-blur-md md:hidden">
      <div className="border-b px-4 py-2.5">
        <AppBrandHeader onMenuClick={toggleSidebar} variant="topbar" />
      </div>
    </div>
  )
}

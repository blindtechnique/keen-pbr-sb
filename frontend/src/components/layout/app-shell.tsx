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
      {/* KeeneticOS scrolls the content, not the document: the header and the
          menu are outside the scrolling box rather than pinned on top of it, so
          there is no page-level scrollbar at all. */}
      <div
        className={cn(
          "flex h-screen max-h-screen w-full max-w-full overflow-hidden",
          isOverview ? "keen-canvas-overview" : "keen-canvas-page"
        )}
      >
        <a
          className="sr-only z-50 rounded-md bg-background px-3 py-2 text-sm font-medium shadow focus:not-sr-only focus:fixed focus:top-3 focus:left-3"
          href="#main-content"
        >
          Skip to content
        </a>
        <AppSidebar />
        <SidebarInset className="relative flex h-screen max-h-screen max-w-full min-w-0 flex-col overflow-hidden bg-transparent">
          <MobileSidebarHeader />
          <DesktopSystemBar />
          <main
            aria-labelledby="page-title"
            className="min-h-0 min-w-0 flex-1 overflow-y-auto"
            id="main-content"
          >
            {/* No max-width: NDMS lets its panels use the whole window, and a
                centred column left wide screens half empty. The bottom padding
                leaves room for the fixed save bar. */}
            <div
              className="min-w-0 px-4 pt-4 sm:px-6 lg:px-8 lg:pt-5"
              style={{
                paddingBottom:
                  "calc(var(--warning-banner-height, 0px) + 1.25rem)",
              }}
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
    // NDMS: .header { height: 64px; padding: 0 32px } with the shadow cast by
    // a sibling, clipped to show only underneath.
    <div className="keen-header-shadow relative z-30 hidden h-16 shrink-0 items-center justify-between bg-card px-8 md:flex">
      {/* The brand lives once, at the top of the left column above the menu.
          The bar itself carries only the controls on the right. */}
      <span />
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

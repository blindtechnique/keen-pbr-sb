import type { ReactNode } from "react"
import { useLocation } from "wouter"

import { AppSidebar } from "@/components/app-sidebar"
import { AppBrandHeader } from "@/components/layout/app-brand-header"
import { MobileAppHeader } from "@/components/layout/mobile-app-header"
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
          "flex h-screen max-h-screen w-full max-w-full flex-col overflow-hidden",
          isOverview ? "keen-canvas-overview" : "keen-canvas-page"
        )}
      >
        <a
          className="sr-only z-50 rounded-md bg-background px-3 py-2 text-sm font-medium shadow focus:not-sr-only focus:fixed focus:top-3 focus:left-3"
          href="#main-content"
        >
          Skip to content
        </a>
        <DesktopSystemBar />
        <div className="flex min-h-0 w-full max-w-full flex-1 overflow-hidden">
          <AppSidebar />
          <SidebarInset className="relative flex min-h-0 max-w-full min-w-0 flex-col overflow-hidden bg-transparent">
            <MobileSidebarHeader />
            <main
              aria-labelledby="page-title"
              className="min-h-0 min-w-0 flex-1 overflow-y-auto [scrollbar-gutter:stable]"
              id="main-content"
            >
              {/* No max-width: NDMS lets its panels use the whole window, and a
                centred column left wide screens half empty. The bottom padding
                leaves room for the fixed save bar and, when rows are selected,
                for the bulk action bar stacked above it. */}
              <div
                className={cn(
                  "min-w-0 px-4 pt-4 sm:px-6",
                  isOverview
                    ? "lg:px-8 lg:pt-5"
                    : "lg:pt-[33px] lg:pr-8 lg:pl-8"
                )}
                style={{
                  paddingBottom:
                    "calc(var(--warning-banner-height, 0px) + var(--bulk-toolbar-height, 0px) + 1.25rem)",
                }}
              >
                {children}
              </div>
            </main>
            <WarningBanner state={warningBannerState} />
          </SidebarInset>
        </div>
      </div>
    </SidebarProvider>
  )
}

function DesktopSystemBar() {
  return (
    // KeeneticOS: .layout__header — 0..ширина окна, высота 64px, padding 0 32px,
    // белый фон, тень отбрасывается соседом и подрезана снизу. Логотип стоит в
    // ней слева на x=32, а колонка меню начинается уже под шапкой; раньше
    // логотип жил над меню, и шапка начиналась после колонки.
    <div className="keen-header-shadow relative z-30 hidden h-16 w-full shrink-0 items-center justify-between bg-card px-8 md:flex">
      <AppBrandHeader className="min-w-0" />
      <TopBarControls />
    </div>
  )
}

function MobileSidebarHeader() {
  const { openMobile, toggleSidebar } = useSidebar()

  return (
    // The page itself scrolls inside <main>, so this sibling never moves.
    // Keeping it in normal layout avoids a fixed overlay covering the sticky
    // action bar after mobile overscroll or history restoration.
    <div className="relative z-40 flex h-16 shrink-0 md:hidden">
      <MobileAppHeader menuOpen={openMobile} onMenuClick={toggleSidebar} />
    </div>
  )
}

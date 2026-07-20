"use client"

import type { ComponentProps } from "react"
import {
  LayoutGridIcon,
  LogOutIcon,
  ShieldIcon,
  WaypointsIcon,
} from "lucide-react"
import { useTranslation } from "react-i18next"

import { AppBrandHeader } from "@/components/layout/app-brand-header"
import { NavMain } from "@/components/nav-main"
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
} from "@/components/ui/sidebar"
import { useSidebar } from "@/components/ui/sidebar-context"
import { Button } from "@/components/ui/button"

export function AppSidebar(props: ComponentProps<typeof Sidebar>) {
  const { isMobile, toggleSidebar } = useSidebar()
  const { t } = useTranslation()

  const data = {
    navMain: [
      {
        title: t("nav.groups.general"),
        url: "#",
        icon: LayoutGridIcon,
        items: [
          {
            title: t("nav.items.systemMonitor"),
            url: "/",
          },
          {
            title: t("nav.items.settings"),
            url: "/general",
          },
        ],
      },
      {
        title: t("nav.groups.internet"),
        url: "#",
        icon: WaypointsIcon,
        items: [
          {
            title: t("nav.items.outbounds"),
            url: "/outbounds",
          },
          {
            title: t("nav.items.transports"),
            url: "/transports",
          },
          {
            title: t("nav.items.connections"),
            url: "/connections",
          },
          {
            title: "nfqws2",
            url: "/nfqws",
          },
          {
            title: t("nav.items.dnsServers"),
            url: "/dns-servers",
          },
        ],
      },
      {
        title: t("nav.groups.networkRules"),
        url: "#",
        icon: ShieldIcon,
        items: [
          {
            title: t("nav.items.catalog"),
            url: "/catalog",
          },
          {
            title: t("nav.items.lists"),
            url: "/lists",
          },
          {
            title: t("nav.items.routingRules"),
            url: "/routing-rules",
          },
        ],
      },
    ],
  }

  return (
    <Sidebar collapsible="icon" {...props}>
      <SidebarHeader className={isMobile ? "h-16 bg-card px-4 py-2" : "h-16 justify-center bg-card px-4 py-0 group-data-[collapsible=icon]:px-2"}>
        <SidebarMenuHeader isMobile={isMobile} onMenuClick={toggleSidebar} />
      </SidebarHeader>
      {/* No horizontal padding: in KeeneticOS the selected row runs from the
          screen edge all the way to the hairline, and any padding here leaves
          it floating in the middle of the column. */}
      <SidebarContent className="border-r px-0 py-0">
        <NavMain items={data.navMain} />
      </SidebarContent>
      {/* The footer is the button: padding here would leave a pale margin
          around the hover fill instead of letting it reach the edges. */}
      <SidebarFooter className={isMobile ? "border-t px-4 py-3" : "border-t border-r bg-sidebar p-0 group-data-[collapsible=icon]:hidden"}>
        <div>
          <Button
            className="h-12 w-full justify-start rounded-none bg-sidebar px-4 text-[14px] font-normal text-primary hover:bg-[#EDEDED] hover:text-primary"
            onClick={async () => {
              await fetch("/api/auth/logout", { method: "POST" })
              window.location.assign("/")
            }}
            variant="ghost"
          >
            <LogOutIcon />
            {t("auth.signOut")}
          </Button>
        </div>
      </SidebarFooter>
    </Sidebar>
  )
}

function SidebarMenuHeader({
  isMobile,
  onMenuClick,
}: {
  isMobile: boolean
  onMenuClick: () => void
}) {
  if (isMobile) {
    return <AppBrandHeader onMenuClick={onMenuClick} />
  }

  return <AppBrandHeader />
}

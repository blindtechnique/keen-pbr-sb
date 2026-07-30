"use client"

import type { ComponentProps } from "react"
import { LayoutGridIcon, ShieldIcon, WaypointsIcon } from "lucide-react"
import { useTranslation } from "react-i18next"

import { AppBrandHeader } from "@/components/layout/app-brand-header"
import { SidebarToggleButton } from "@/components/layout/sidebar-toggle-button"
import { MobileMenuControls } from "@/components/layout/top-bar-controls"
import { NavMain } from "@/components/nav-main"
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
} from "@/components/ui/sidebar"
import { useSidebar } from "@/components/ui/sidebar-context"

export function AppSidebar(props: ComponentProps<typeof Sidebar>) {
  const { isMobile, state, toggleSidebar } = useSidebar()
  const { t } = useTranslation()
  const collapsed = !isMobile && state === "collapsed"

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
            title: "nfqws2",
            url: "/nfqws",
          },
          {
            title: t("nav.items.connections"),
            url: "/connections",
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
          {
            title: t("nav.items.dnsRules"),
            url: "/dns-rules",
          },
        ],
      },
    ],
  }

  return (
    <Sidebar className="keen-app-sidebar z-40" collapsible="icon" {...props}>
      {!isMobile ? (
        <SidebarHeader className="keen-sidebar-brand relative z-20 h-16 w-[264px] min-w-[264px] justify-center bg-card py-0 pr-4 pl-8">
          <AppBrandHeader />
        </SidebarHeader>
      ) : null}
      {/* No horizontal padding: in KeeneticOS the selected row runs from the
          screen edge all the way to the hairline, and any padding here leaves
          it floating in the middle of the column. */}
      <SidebarContent className="keen-sidebar-divider px-0 py-0">
        <NavMain items={data.navMain} />
      </SidebarContent>
      {/* The footer is the button: padding here would leave a pale margin
          around the hover fill instead of letting it reach the edges. */}
      {isMobile ? (
        <SidebarFooter className="keen-sidebar-toggle h-16 shrink-0 bg-sidebar p-0">
          <MobileMenuControls />
        </SidebarFooter>
      ) : (
        <SidebarFooter className="keen-sidebar-toggle h-16 shrink-0 bg-sidebar p-0">
          <SidebarToggleButton
            expanded={!collapsed}
            label={collapsed ? t("brand.showMenu") : t("brand.hideMenu")}
            onClick={toggleSidebar}
          />
        </SidebarFooter>
      )}
    </Sidebar>
  )
}

"use client"

import type { ComponentProps } from "react"
import { LayoutGridIcon, ShieldIcon, WaypointsIcon } from "lucide-react"
import { useTranslation } from "react-i18next"

import { AppBrandHeader } from "@/components/layout/app-brand-header"
import {
  KeeneticMenuArrowIcon,
  KeeneticMenuIcon,
} from "@/components/layout/keenetic-menu-icons"
import { MobileMenuControls } from "@/components/layout/top-bar-controls"
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
        ],
      },
    ],
  }

  return (
    <Sidebar className="z-40" collapsible="icon" {...props}>
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
          <Button
            aria-label={collapsed ? t("brand.showMenu") : t("brand.hideMenu")}
            className="h-16 w-full justify-start gap-3 rounded-none bg-sidebar px-6 text-[16px] leading-[23px] font-bold text-primary group-data-[collapsible=icon]:justify-center group-data-[collapsible=icon]:px-0 hover:bg-sidebar-accent hover:text-primary"
            onClick={toggleSidebar}
            title={collapsed ? t("brand.showMenu") : t("brand.hideMenu")}
            variant="ghost"
          >
            {collapsed ? (
              <KeeneticMenuIcon className="shrink-0" />
            ) : (
              <KeeneticMenuArrowIcon className="ml-0.5 shrink-0" />
            )}
            <span className="group-data-[collapsible=icon]:hidden">
              {t("brand.hideMenu")}
            </span>
          </Button>
        </SidebarFooter>
      )}
    </Sidebar>
  )
}

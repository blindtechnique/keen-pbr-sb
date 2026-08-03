"use client"

import type { ComponentProps } from "react"
import { LayoutGridIcon, ShieldIcon, WaypointsIcon } from "lucide-react"
import { useTranslation } from "react-i18next"

import { SidebarToggleButton } from "@/components/layout/sidebar-toggle-button"
import { MobileMenuControls } from "@/components/layout/top-bar-controls"
import { NavMain } from "@/components/nav-main"
import { Sidebar, SidebarContent, SidebarFooter } from "@/components/ui/sidebar"
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
      {/* Логотип на десктопе живёт в шапке, а не над колонкой меню: в
          KeeneticOS шапка идёт во всю ширину окна, логотип стоит в ней слева
          на x=32, а меню начинается уже под шапкой. */}
      {/* No horizontal padding: in KeeneticOS the selected row runs from the
          screen edge all the way to the hairline, and any padding here leaves
          it floating in the middle of the column. */}
      <SidebarContent className="keen-sidebar-divider px-0 py-0">
        <NavMain items={data.navMain} />
      </SidebarContent>
      {/* The footer is the button: padding here would leave a pale margin
          around the hover fill instead of letting it reach the edges. */}
      {isMobile ? (
        // Высоту не фиксируем: строки с подписями занимают четыре ряда, а не
        // один ряд иконок.
        <SidebarFooter className="keen-sidebar-toggle shrink-0 bg-sidebar p-0">
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

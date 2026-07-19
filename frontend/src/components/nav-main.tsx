"use client"

import { type LucideIcon } from "lucide-react"
import { useLocation } from "wouter"

import {
  SidebarGroup,
  SidebarGroupContent,
  SidebarMenu,
  SidebarMenuItem,
  SidebarMenuSub,
  SidebarMenuSubButton,
  SidebarMenuSubItem,
} from "@/components/ui/sidebar"
import { useSidebar } from "@/components/ui/sidebar-context"
import { matchesNavHref } from "@/lib/nav-active"

export function NavMain({
  items,
}: {
  items: {
    title: string
    url: string
    icon?: LucideIcon
    items?: {
      title: string
      url: string
    }[]
  }[]
}) {
  const [location, navigate] = useLocation()
  const { isMobile, setOpenMobile } = useSidebar()

  return (
    <SidebarGroup>
      <SidebarGroupContent>
        <SidebarMenu>
          {items.map((item) => {
            const Icon = item.icon
            const hasChildren = Boolean(item.items?.length)

            return (
              <SidebarMenuItem key={item.title}>
                <div className="flex h-10 items-center gap-2.5 px-2 text-xs font-semibold tracking-[0.03em] text-primary uppercase group-data-[collapsible=icon]:h-[4.5rem] group-data-[collapsible=icon]:justify-center group-data-[collapsible=icon]:border-b group-data-[collapsible=icon]:px-0">
                  {Icon ? <Icon className="size-4 text-primary" /> : null}
                  <span className="group-data-[collapsible=icon]:hidden">{item.title}</span>
                </div>
                {hasChildren ? (
                  <SidebarMenuSub className="mx-1 border-l-0 px-0">
                    {item.items?.map((subItem) => {
                      const navActive = matchesNavHref(location, subItem.url)

                      return (
                        <SidebarMenuSubItem key={subItem.title}>
                          <SidebarMenuSubButton
                            aria-current={navActive ? "page" : undefined}
                            className={
                              navActive
                                ? "min-h-9 rounded-none border-0 bg-sidebar-accent px-3 text-sm font-medium text-sidebar-accent-foreground"
                                : "min-h-9 rounded-none border-0 px-3 text-sm text-sidebar-foreground/85 hover:bg-sidebar-accent/70"
                            }
                            data-nav-item={subItem.url}
                            href={subItem.url}
                            isActive={navActive}
                            onClick={(event) => {
                              event.preventDefault()
                              navigate(subItem.url)
                              if (isMobile) {
                                setOpenMobile(false)
                              }
                            }}
                          >
                            <span>{subItem.title}</span>
                          </SidebarMenuSubButton>
                        </SidebarMenuSubItem>
                      )
                    })}
                  </SidebarMenuSub>
                ) : null}
              </SidebarMenuItem>
            )
          })}
        </SidebarMenu>
      </SidebarGroupContent>
    </SidebarGroup>
  )
}

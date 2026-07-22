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
                <div className="flex h-12 items-center gap-2.5 px-[22px] text-[12px] leading-[18px] font-bold text-primary group-data-[collapsible=icon]:h-[4.5rem] group-data-[collapsible=icon]:justify-center group-data-[collapsible=icon]:border-b group-data-[collapsible=icon]:px-0">
                  {Icon ? <Icon className="size-6 text-primary" /> : null}
                  <span className="group-data-[collapsible=icon]:hidden">
                    {item.title}
                  </span>
                </div>
                {hasChildren ? (
                  <SidebarMenuSub className="mx-0 translate-x-0 border-l-0 px-0">
                    {item.items?.map((subItem) => {
                      const navActive = matchesNavHref(location, subItem.url)

                      return (
                        <SidebarMenuSubItem key={subItem.title}>
                          <SidebarMenuSubButton
                            aria-current={navActive ? "page" : undefined}
                            className={
                              navActive
                                ? "h-9 min-h-9 translate-x-0 rounded-none border-0 bg-sidebar-accent px-6 text-[14px] leading-6 font-normal text-sidebar-accent-foreground"
                                : "h-9 min-h-9 translate-x-0 rounded-none border-0 px-6 text-[14px] leading-6 font-normal text-foreground hover:bg-[#F0F0F0]"
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

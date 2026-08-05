"use client"

import { useState } from "react"
import { type LucideIcon } from "lucide-react"
import { useTranslation } from "react-i18next"
import { useLocation } from "wouter"

import { SidebarToggleButton } from "@/components/layout/sidebar-toggle-button"
import { Button } from "@/components/ui/button"
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet"
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
import { cn } from "@/lib/utils"

type NavSubItem = {
  title: string
  url: string
  /** Адреса редакторов, оставшиеся от прежних отдельных страниц. */
  aliases?: string[]
}

type NavItem = {
  title: string
  url: string
  icon?: LucideIcon
  items?: NavSubItem[]
}

export function NavMain({ items }: { items: NavItem[] }) {
  const [location, navigate] = useLocation()
  const { t } = useTranslation()
  const { isMobile, setOpen, setOpenMobile, state } = useSidebar()
  const [openGroup, setOpenGroup] = useState<string | null>(null)
  const collapsed = !isMobile && state === "collapsed"

  const navigateTo = (url: string) => {
    navigate(url)
    setOpenGroup(null)
    if (isMobile) {
      setOpenMobile(false)
    }
  }

  if (!collapsed) {
    return (
      <ExpandedNavigation
        items={items}
        location={location}
        onNavigate={navigateTo}
      />
    )
  }

  const selectedGroup = items.find((item) => item.title === openGroup) ?? null

  return (
    <>
      <CollapsedNavigationRail
        items={items}
        location={location}
        onOpenGroup={(title) => setOpenGroup(title)}
        openGroup={openGroup}
      />
      <Sheet
        onOpenChange={(open) => {
          if (!open) setOpenGroup(null)
        }}
        open={selectedGroup !== null}
      >
        <SheetContent
          className="keen-desktop-menu-overlay gap-0 bg-sidebar p-0 text-sidebar-foreground shadow-none"
          overlayClassName="keen-desktop-menu-backdrop"
          showCloseButton={false}
          side="left"
        >
          <SheetHeader className="sr-only">
            <SheetTitle>
              {selectedGroup?.title ?? t("brand.showMenu")}
            </SheetTitle>
            <SheetDescription>{t("brand.showMenu")}</SheetDescription>
          </SheetHeader>
          <div className="flex min-h-0 flex-1 flex-col">
            <nav
              aria-label={selectedGroup?.title}
              className="min-h-0 flex-1 overflow-x-hidden overflow-y-auto"
            >
              {items.map((item) => (
                <OverlayNavigationGroup
                  item={item}
                  key={item.title}
                  location={location}
                  onNavigate={navigateTo}
                  onSelect={() => setOpenGroup(item.title)}
                  selected={item.title === selectedGroup?.title}
                />
              ))}
            </nav>
            <div className="keen-sidebar-toggle h-16 shrink-0 bg-sidebar">
              <SidebarToggleButton
                expanded={false}
                label={t("brand.showMenu")}
                onClick={() => {
                  setOpenGroup(null)
                  setOpen(true)
                }}
              />
            </div>
          </div>
        </SheetContent>
      </Sheet>
    </>
  )
}

function CollapsedNavigationRail({
  items,
  location,
  onOpenGroup,
  openGroup,
}: {
  items: NavItem[]
  location: string
  onOpenGroup: (title: string) => void
  openGroup: string | null
}) {
  return (
    <SidebarGroup className="p-0">
      <SidebarGroupContent>
        <SidebarMenu>
          {items.map((item) => {
            const Icon = item.icon
            const groupActive = isGroupActive(item, location)

            return (
              <SidebarMenuItem className="keen-nav-rail-group" key={item.title}>
                <Button
                  aria-expanded={openGroup === item.title}
                  aria-haspopup="dialog"
                  aria-label={item.title}
                  className={cn(
                    "h-[72px] w-[72px] rounded-none border-0 p-0 text-primary hover:bg-sidebar-accent hover:text-primary",
                    groupActive ? "bg-sidebar-accent" : "bg-sidebar"
                  )}
                  onClick={() => onOpenGroup(item.title)}
                  title={item.title}
                  type="button"
                  variant="ghost"
                >
                  {Icon ? <Icon className="size-6" strokeWidth={2.5} /> : null}
                </Button>
              </SidebarMenuItem>
            )
          })}
        </SidebarMenu>
      </SidebarGroupContent>
    </SidebarGroup>
  )
}

function ExpandedNavigation({
  items,
  location,
  onNavigate,
}: {
  items: NavItem[]
  location: string
  onNavigate: (url: string) => void
}) {
  return (
    <SidebarGroup className="p-0">
      <SidebarGroupContent>
        <SidebarMenu>
          {items.map((item) => {
            const Icon = item.icon
            const hasChildren = Boolean(item.items?.length)

            return (
              <SidebarMenuItem key={item.title}>
                <div className="flex h-12 items-center gap-3 px-6 text-[12px] leading-[18px] font-bold text-primary uppercase">
                  {Icon ? (
                    <Icon className="size-5 shrink-0 text-primary" />
                  ) : null}
                  <span>{item.title}</span>
                </div>
                {hasChildren ? (
                  <SidebarMenuSub className="mx-0 translate-x-0 border-l-0 px-0">
                    {item.items?.map((subItem) => {
                      const navActive = matchesNavHref(
                        location,
                        subItem.url,
                        subItem.aliases
                      )

                      return (
                        <SidebarMenuSubItem key={subItem.title}>
                          <SidebarMenuSubButton
                            aria-current={navActive ? "page" : undefined}
                            className={cn(
                              "h-9 min-h-9 translate-x-0 rounded-none border-0 px-6 text-[14px] leading-6 font-normal",
                              navActive
                                ? "bg-sidebar-accent text-sidebar-accent-foreground"
                                : "text-sidebar-foreground"
                            )}
                            data-nav-item={subItem.url}
                            href={subItem.url}
                            isActive={navActive}
                            onClick={(event) => {
                              event.preventDefault()
                              onNavigate(subItem.url)
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

function OverlayNavigationGroup({
  item,
  location,
  onNavigate,
  onSelect,
  selected,
}: {
  item: NavItem
  location: string
  onNavigate: (url: string) => void
  onSelect: () => void
  selected: boolean
}) {
  const Icon = item.icon
  const groupActive = isGroupActive(item, location)

  return (
    <section className="keen-nav-overlay-group">
      <button
        aria-expanded={selected}
        className={cn(
          "flex w-full items-center gap-3 px-6 text-left text-[14px] leading-[22px] font-bold text-primary uppercase",
          selected ? "h-12" : "h-[72px]",
          groupActive && !selected ? "bg-sidebar-accent" : "bg-sidebar"
        )}
        onClick={onSelect}
        type="button"
      >
        {Icon ? <Icon className="size-5 shrink-0" /> : null}
        <span>{item.title}</span>
      </button>
      {selected ? (
        <ul aria-label={item.title}>
          {item.items?.map((subItem) => {
            const navActive = matchesNavHref(
              location,
              subItem.url,
              subItem.aliases
            )
            return (
              <li key={subItem.title}>
                <button
                  aria-current={navActive ? "page" : undefined}
                  className={cn(
                    "flex h-9 w-full items-center px-6 text-left text-[14px] leading-6 text-sidebar-foreground",
                    navActive ? "bg-sidebar-accent" : "hover:bg-[#f0f0f0]"
                  )}
                  onClick={() => onNavigate(subItem.url)}
                  type="button"
                >
                  {subItem.title}
                </button>
              </li>
            )
          })}
        </ul>
      ) : null}
    </section>
  )
}

function isGroupActive(item: NavItem, location: string) {
  return Boolean(
    item.items?.some((subItem) =>
      matchesNavHref(location, subItem.url, subItem.aliases)
    )
  )
}

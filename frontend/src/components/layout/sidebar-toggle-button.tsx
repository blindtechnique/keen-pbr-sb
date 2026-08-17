import type { ComponentProps } from "react"

import {
  KeeneticMenuArrowIcon,
  KeeneticMenuIcon,
} from "@/components/layout/keenetic-menu-icons"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"

export function SidebarToggleButton({
  expanded,
  label,
  className,
  ...props
}: Omit<ComponentProps<typeof Button>, "children" | "title"> & {
  readonly expanded: boolean
  readonly label: string
}) {
  return (
    <Button
      aria-label={label}
      className={cn("keen-sidebar-toggle-button", className)}
      title={label}
      type="button"
      variant="ghost"
      {...props}
    >
      {expanded ? (
        <KeeneticMenuArrowIcon className="ml-0.5 shrink-0" />
      ) : (
        <KeeneticMenuIcon className="shrink-0" />
      )}
      <span className="group-data-[collapsible=icon]:hidden">{label}</span>
    </Button>
  )
}

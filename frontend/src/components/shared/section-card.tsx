import type { ReactNode } from "react"

import {
  Card,
  CardDescription,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { cn } from "@/lib/utils"

export function SectionCard({
  title,
  children,
  action,
  description,
  className,
  contentClassName,
  // Cards are reserved for the system overview; every other page renders the
  // same sections flat, the way KeeneticOS does.
  flat = false,
}: {
  title: string
  children: ReactNode
  action?: ReactNode
  description?: ReactNode
  className?: string
  contentClassName?: string
  flat?: boolean
}) {
  return (
    <Card
      className={cn(
        flat && "gap-4 rounded-none border-0 bg-transparent p-0 shadow-none",
        className
      )}
    >
      <CardHeader className={cn(flat && "px-0")}>
        <div className="flex items-center justify-between gap-3">
          <div className="space-y-1">
            <CardTitle>{title}</CardTitle>
            {description ? (
              <CardDescription>{description}</CardDescription>
            ) : null}
          </div>
          {action}
        </div>
      </CardHeader>
      <CardContent className={cn("space-y-3", flat && "px-0", contentClassName)}>
        {children}
      </CardContent>
    </Card>
  )
}

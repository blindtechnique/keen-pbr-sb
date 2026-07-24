import type { ReactNode } from "react"

import { cn } from "@/lib/utils"

export type KeeneticStatusTone = "neutral" | "success"

export function KeeneticStatus({
  children,
  className,
  tone = "neutral",
}: {
  children: ReactNode
  className?: string
  tone?: KeeneticStatusTone
}) {
  return (
    <span
      className={cn(
        "keenetic-status",
        tone === "success" && "keenetic-status--success",
        className
      )}
      role="status"
    >
      <span aria-hidden="true" className="keenetic-status__dot" />
      <span>{children}</span>
    </span>
  )
}

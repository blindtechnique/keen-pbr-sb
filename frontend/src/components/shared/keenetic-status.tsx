import type { ReactNode } from "react"

import { cn } from "@/lib/utils"

export type KeeneticStatusTone = "neutral" | "success"

export function KeeneticStatus({
  children,
  className,
  title,
  tone = "neutral",
}: {
  children: ReactNode
  className?: string
  /** Полная формулировка, когда в плашку помещается только короткая. */
  title?: string
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
      title={title}
    >
      <span aria-hidden="true" className="keenetic-status__dot" />
      <span>{children}</span>
    </span>
  )
}

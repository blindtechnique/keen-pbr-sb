import { cn } from "@/lib/utils"

import { getProtocolVisualMark } from "@/components/transports/protocol-visual"

export function TransportProtocolIcon({
  protocol,
  className,
}: {
  readonly protocol: string | null | undefined
  readonly className?: string
}) {
  const label = protocol?.trim() || "Unknown protocol"
  const mark = getProtocolVisualMark(protocol)

  return (
    <span
      aria-label={label}
      className={cn(
        "inline-flex h-6 shrink-0 items-center justify-center rounded-[3px] border border-primary/35 bg-primary/5 px-1.5 text-[10px] leading-none font-bold tracking-[0.02em] whitespace-nowrap text-primary",
        className
      )}
      role="img"
      title={label}
    >
      {mark}
    </span>
  )
}

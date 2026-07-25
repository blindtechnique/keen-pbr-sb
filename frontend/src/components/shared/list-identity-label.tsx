import type { ConfigObject } from "@/api/generated/model/configObject"
import { getListDisplayName } from "@/lib/list-display"
import { cn } from "@/lib/utils"

export function ListIdentityLabel({
  className,
  lists,
  technicalId,
}: {
  className?: string
  lists: ConfigObject["lists"]
  technicalId: string
}) {
  const displayName = getListDisplayName(technicalId, lists)
  const hasDistinctDisplayName = displayName !== technicalId

  return (
    <span
      className={cn(
        "flex max-w-full min-w-0 flex-col items-start leading-tight",
        className
      )}
      title={
        hasDistinctDisplayName ? `${displayName} (${technicalId})` : technicalId
      }
    >
      <span className="max-w-full truncate">{displayName}</span>
      {hasDistinctDisplayName ? (
        <span className="max-w-full truncate font-mono text-xs font-normal text-muted-foreground">
          {technicalId}
        </span>
      ) : null}
    </span>
  )
}

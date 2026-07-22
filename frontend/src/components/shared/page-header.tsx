import type { ReactNode } from "react"

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string
  description: string
  actions?: ReactNode
}) {
  return (
    <header className="mb-2 flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
      <div className="min-w-0">
        {/* NDMS sets page titles in 28px Roboto Bold and gives the description
            its own 72px band in plain black - not the small grey subtitle we
            had, which read as a caption rather than as part of the page. */}
        <h1
          className="text-balance text-[28px] leading-[36px] font-bold text-foreground"
          id="page-title"
        >
          {title}
        </h1>
        <div className="flex min-h-[72px] items-start">
          <p className="mt-2 max-w-[110ch] text-pretty text-[14px] leading-[22px] text-foreground">
            {description}
          </p>
        </div>
      </div>
      {actions ? <div className="md:mt-2 md:shrink-0">{actions}</div> : null}
    </header>
  )
}

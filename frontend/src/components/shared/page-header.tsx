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
    <header className="mb-6 flex flex-col gap-4 border-b border-border/80 pb-5 md:mb-7 md:flex-row md:items-end md:justify-between">
      <div className="min-w-0">
        <h1
          className="text-balance text-[1.75rem] font-semibold tracking-[-0.025em] text-foreground md:text-[1.65rem]"
          id="page-title"
        >
          {title}
        </h1>
        <p className="mt-1.5 max-w-[68ch] text-pretty text-sm leading-6 text-muted-foreground">
          {description}
        </p>
      </div>
      {actions}
    </header>
  )
}

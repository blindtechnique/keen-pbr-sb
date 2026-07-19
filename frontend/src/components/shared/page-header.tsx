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
    <header className="mb-4 flex flex-col gap-3 border-b border-border/80 pb-3 md:flex-row md:items-end md:justify-between">
      <div className="min-w-0">
        <h1
          className="text-balance text-[1.375rem] leading-7 font-medium tracking-[-0.01em] text-foreground"
          id="page-title"
        >
          {title}
        </h1>
        <p className="mt-1 max-w-[68ch] text-pretty text-[13px] leading-5 text-muted-foreground">
          {description}
        </p>
      </div>
      {actions}
    </header>
  )
}

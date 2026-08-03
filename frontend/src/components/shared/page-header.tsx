import type { ReactNode } from "react"

import { useDocumentTitle } from "@/hooks/use-document-title"

export function PageHeader({
  title,
  description,
  actions,
  documentTitle,
}: {
  title: ReactNode
  description: string
  actions?: ReactNode
  // Pages whose heading is not a plain string pass the tab text explicitly.
  documentTitle?: string
}) {
  useDocumentTitle(
    documentTitle ?? (typeof title === "string" ? title : undefined)
  )

  return (
    <header className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
      <div className="min-w-0">
        <h1
          className="text-[28px] leading-[36px] font-bold text-balance text-foreground"
          id="page-title"
        >
          {title}
        </h1>
        <p className="mt-2 max-w-[110ch] text-[14px] leading-[22px] text-pretty text-foreground">
          {description}
        </p>
      </div>
      {actions ? <div className="md:mt-2 md:shrink-0">{actions}</div> : null}
    </header>
  )
}

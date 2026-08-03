import type { ReactNode } from "react"

import { HelpHint } from "@/components/shared/help-hint"
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
      {/* Описание раздела ушло под «ⓘ» рядом с заголовком: его читают один раз,
          а вертикаль оно занимало всегда и на каждой странице. */}
      <div className="flex min-w-0 items-start gap-1">
        <h1
          className="min-w-0 text-[28px] leading-[36px] font-bold text-balance text-foreground"
          id="page-title"
        >
          {title}
        </h1>
        <HelpHint text={description} />
      </div>
      {actions ? <div className="md:shrink-0">{actions}</div> : null}
    </header>
  )
}

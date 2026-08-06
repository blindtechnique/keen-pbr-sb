import { ArrowRight } from "lucide-react"

/** «Было → станет» одной строкой — общий вид для диалогов «что сломается». */
export function ChangeValue({
  after,
  before,
}: {
  after: string
  before: string
}) {
  return (
    <span className="inline-flex min-w-0 items-center gap-1 leading-4">
      <span className="min-w-0 truncate">{before}</span>
      <ArrowRight className="mt-px size-3 shrink-0" />
      <span className="min-w-0 truncate">{after}</span>
    </span>
  )
}

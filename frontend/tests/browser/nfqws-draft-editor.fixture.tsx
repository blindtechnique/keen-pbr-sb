import {
  QueryClient,
  QueryClientProvider,
  useQuery,
} from "@tanstack/react-query"
import type { ComponentProps } from "react"
import { createRoot } from "react-dom/client"
import { StrategiesEditor } from "@/pages/nfqws-page"
import { initI18n } from "@/i18n"

const client = new QueryClient({
  defaultOptions: { queries: { retry: false } },
})
const ignoreDirty = () => {}
const forbidApply = async () => {
  throw new Error("This editor regression must never apply a strategy")
}

export function Fixture() {
  const query = useQuery<ComponentProps<typeof StrategiesEditor>["status"]>({
    queryKey: ["fixture-status"],
    queryFn: async () => (await fetch("/api/nfqws")).json(),
  })
  if (!query.data) return null
  return (
    <StrategiesEditor
      onDirtyChange={ignoreDirty}
      refresh={() => void query.refetch()}
      runOperation={forbidApply}
      status={query.data}
    />
  )
}

localStorage.setItem("language", "ru")
await initI18n()
createRoot(document.getElementById("root")!).render(
  <QueryClientProvider client={client}>
    <Fixture />
  </QueryClientProvider>
)

import { useEffect, useRef } from "react"
import { useQueryClient } from "@tanstack/react-query"

import { mountStatusEventSession } from "@/api/status-event-session"

export function StatusEventBridge() {
  const queryClient = useQueryClient()
  const lastConfigResyncOperationRef = useRef<string | null>(null)

  useEffect(
    () => mountStatusEventSession(queryClient, lastConfigResyncOperationRef),
    [queryClient]
  )

  return null
}

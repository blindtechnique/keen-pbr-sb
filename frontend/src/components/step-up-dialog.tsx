import { LoaderCircleIcon } from "lucide-react"
import { type FormEvent, useCallback, useEffect, useRef, useState } from "react"
import { useTranslation } from "react-i18next"

import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  setStepUpPrompt,
  type StepUpCredentials,
} from "@/lib/step-up"

type PendingPrompt = {
  resolve: (credentials: StepUpCredentials | null) => void
}

/**
 * Asks for the password again before an operation that installs software or
 * changes how the router is reached.
 *
 * Mounted once, near the root. It installs itself as the prompt the API client
 * calls, so no privileged screen has to know this exists - which is the same
 * reason the server enforces the requirement in one pre-routing guard instead
 * of in every handler.
 */
export function StepUpDialog() {
  const { t } = useTranslation()
  const [pending, setPending] = useState<PendingPrompt | null>(null)
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const [submitting, setSubmitting] = useState(false)
  // Held in a ref so the unmount cleanup can settle a prompt that is still
  // open. Leaving it unsettled would hang the request that is awaiting it.
  const pendingRef = useRef<PendingPrompt | null>(null)

  useEffect(() => {
    pendingRef.current = pending
  }, [pending])

  useEffect(() => {
    setStepUpPrompt(
      () =>
        new Promise<StepUpCredentials | null>((resolve) => {
          setUsername("")
          setPassword("")
          setSubmitting(false)
          setPending({ resolve })
        })
    )

    return () => {
      setStepUpPrompt(null)
      pendingRef.current?.resolve(null)
    }
  }, [])

  const settle = useCallback(
    (credentials: StepUpCredentials | null) => {
      const current = pendingRef.current
      setPending(null)
      // The password is not kept after the prompt closes. It is forwarded once
      // and never held for a possible retry.
      setPassword("")
      setSubmitting(false)
      current?.resolve(credentials)
    },
    []
  )

  const handleSubmit = useCallback(
    (event: FormEvent) => {
      event.preventDefault()
      if (submitting) {
        return
      }
      setSubmitting(true)
      settle({ username, password })
    },
    [password, settle, submitting, username]
  )

  return (
    <Dialog
      open={pending !== null}
      onOpenChange={(open) => {
        // Dismissing is a refusal, not a silent no-op: the awaiting request
        // must be told, or it waits forever.
        if (!open) {
          settle(null)
        }
      }}
    >
      <DialogContent className="sm:max-w-md">
        <form onSubmit={handleSubmit}>
          <DialogHeader>
            <DialogTitle>{t("auth.stepUp.title")}</DialogTitle>
            <DialogDescription>
              {t("auth.stepUp.description")}
            </DialogDescription>
          </DialogHeader>

          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <Label htmlFor="step-up-username">{t("auth.username")}</Label>
              <Input
                autoComplete="username"
                id="step-up-username"
                onChange={(event) => setUsername(event.target.value)}
                required
                value={username}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="step-up-password">{t("auth.password")}</Label>
              <Input
                autoComplete="current-password"
                autoFocus
                id="step-up-password"
                onChange={(event) => setPassword(event.target.value)}
                required
                type="password"
                value={password}
              />
            </div>
          </div>

          <DialogFooter>
            <Button
              onClick={() => settle(null)}
              type="button"
              variant="outline"
            >
              {t("common.cancel")}
            </Button>
            <Button disabled={submitting} type="submit">
              {submitting ? (
                <LoaderCircleIcon className="mr-2 size-4 animate-spin" />
              ) : null}
              {t("auth.stepUp.confirm")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

import { LockKeyholeIcon, LoaderCircleIcon } from "lucide-react"
import {
  type FormEvent,
  type ReactNode,
  useCallback,
  useEffect,
  useState,
} from "react"
import { useTranslation } from "react-i18next"

import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"

type AuthStatus = { enabled: boolean; authenticated: boolean }

export function AuthGate({ children }: { children: ReactNode }) {
  const { t } = useTranslation()
  const [status, setStatus] = useState<AuthStatus | null>(null)
  const [username, setUsername] = useState("admin")
  const [password, setPassword] = useState("")
  const [pending, setPending] = useState(false)
  const [error, setError] = useState("")

  const refresh = useCallback(async () => {
    try {
      const response = await fetch("/api/auth/status", { cache: "no-store" })
      if (!response.ok) throw new Error(String(response.status))
      setStatus((await response.json()) as AuthStatus)
    } catch {
      setStatus({ enabled: false, authenticated: true })
    }
  }, [])

  useEffect(() => {
    void refresh()
    const timer = window.setInterval(() => void refresh(), 30_000)
    return () => window.clearInterval(timer)
  }, [refresh])

  const submit = async (event: FormEvent) => {
    event.preventDefault()
    setPending(true)
    setError("")
    try {
      const response = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      })
      if (!response.ok) {
        setError(t("auth.invalidCredentials"))
        return
      }
      setPassword("")
      await refresh()
    } catch {
      setError(t("auth.unavailable"))
    } finally {
      setPending(false)
    }
  }

  if (!status) {
    return (
      <div className="grid min-h-screen place-items-center">
        <LoaderCircleIcon className="size-7 animate-spin text-muted-foreground" />
      </div>
    )
  }
  if (!status.enabled || status.authenticated) return children

  return (
    <main className="grid min-h-screen place-items-center bg-muted/30 p-4">
      <Card className="w-full max-w-md">
        <CardHeader>
          <div className="mb-2 flex size-11 items-center justify-center rounded-xl bg-primary text-primary-foreground">
            <LockKeyholeIcon className="size-5" />
          </div>
          <CardTitle>{t("auth.title")}</CardTitle>
          <CardDescription>{t("auth.description")}</CardDescription>
        </CardHeader>
        <CardContent>
          <form className="space-y-4" onSubmit={submit}>
            <div className="space-y-2">
              <Label htmlFor="auth-username">{t("auth.username")}</Label>
              <Input
                autoComplete="username"
                id="auth-username"
                onChange={(event) => setUsername(event.target.value)}
                required
                value={username}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="auth-password">{t("auth.password")}</Label>
              <Input
                autoComplete="current-password"
                id="auth-password"
                onChange={(event) => setPassword(event.target.value)}
                required
                type="password"
                value={password}
              />
            </div>
            {error ? (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            ) : null}
            <Button className="w-full" disabled={pending} type="submit">
              {pending ? t("auth.signingIn") : t("auth.signIn")}
            </Button>
            <p className="text-xs text-muted-foreground">
              {t("auth.credentialsHint")}
            </p>
          </form>
        </CardContent>
      </Card>
    </main>
  )
}

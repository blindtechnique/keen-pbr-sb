import { LoaderCircleIcon } from "lucide-react"
import {
  type FormEvent,
  type ReactNode,
  useCallback,
  useEffect,
  useState,
} from "react"
import { useTranslation } from "react-i18next"

import logoUrl from "@/assets/logo.png"
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
    <main className="grid min-h-screen bg-background lg:grid-cols-[minmax(20rem,0.8fr)_minmax(28rem,1.2fr)]">
      <section className="relative hidden overflow-hidden bg-[#145a96] p-12 text-white lg:flex lg:flex-col lg:justify-between">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_20%_10%,rgb(100_181_246_/_0.42),transparent_38%),linear-gradient(145deg,#1976d2,#123d63)]" />
        <div className="relative">
          <div className="mb-5 size-20 overflow-hidden rounded-2xl border border-white/25 shadow-lg">
            <img alt={t("brand.logoAlt")} className="size-full object-cover" src={logoUrl} />
          </div>
          <p className="text-sm font-semibold tracking-[0.18em] text-blue-100 uppercase">
            Keenetic / Netcraze
          </p>
          <h1 className="mt-3 text-4xl font-semibold tracking-[-0.04em]">
            keen-pbr-sb
          </h1>
          <p className="mt-4 max-w-md text-base leading-7 text-blue-100">
            {t("brand.tagline")}
          </p>
        </div>
        <p className="relative text-xs text-blue-100/80">Entware · Local control</p>
      </section>
      <div className="grid place-items-center p-4 sm:p-8">
      <Card className="w-full max-w-md">
        <CardHeader>
          <div className="mb-2 size-14 overflow-hidden rounded-xl border border-primary/25 shadow-sm">
            <img alt={t("brand.logoAlt")} className="size-full object-cover" src={logoUrl} />
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
      </div>
    </main>
  )
}

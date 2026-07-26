import { EyeIcon, EyeOffIcon, LoaderCircleIcon } from "lucide-react"
import {
  type FormEvent,
  type HTMLInputTypeAttribute,
  type ReactNode,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react"
import { useTranslation } from "react-i18next"

import { useLanguage } from "@/components/language-provider"
import { Button } from "@/components/ui/button"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Input } from "@/components/ui/input"
import { parseAuthStatus, type AuthStatus } from "@/lib/auth-status"
import { cn } from "@/lib/utils"

const LANGUAGE_OPTIONS = [
  { value: "ru", label: "Русский" },
  { value: "en", label: "English" },
] as const

type AuthInputProps = {
  autoComplete: string
  error?: boolean
  id: string
  label: string
  onChange: (value: string) => void
  required?: boolean
  type?: HTMLInputTypeAttribute
  value: string
}

function AuthInput({
  autoComplete,
  error = false,
  id,
  label,
  onChange,
  required = false,
  type = "text",
  value,
}: AuthInputProps) {
  const { t } = useTranslation()
  const [passwordVisible, setPasswordVisible] = useState(false)
  const isPassword = type === "password"
  const resolvedType = isPassword && passwordVisible ? "text" : type

  return (
    <div className="relative">
      <Input
        aria-invalid={error}
        autoComplete={autoComplete}
        className={cn(
          "peer h-14 rounded-[4px] bg-card px-4 pt-1 text-base shadow-none transition-[border-color,box-shadow] placeholder:text-transparent hover:shadow-none focus-visible:ring-0 sm:h-16 sm:text-[17px]",
          isPassword && "pr-13"
        )}
        id={id}
        onChange={(event) => onChange(event.target.value)}
        placeholder=" "
        required={required}
        type={resolvedType}
        value={value}
      />
      <label
        className="pointer-events-none absolute top-0 left-3 z-10 -translate-y-1/2 bg-card px-1 text-[13px] leading-5 text-muted-foreground transition-[top,transform,font-size,color,padding,background-color] peer-placeholder-shown:top-1/2 peer-placeholder-shown:-translate-y-1/2 peer-placeholder-shown:bg-transparent peer-placeholder-shown:px-1 peer-placeholder-shown:text-base peer-focus:top-0 peer-focus:-translate-y-1/2 peer-focus:bg-card peer-focus:px-1 peer-focus:text-[13px] peer-focus:text-primary sm:text-sm sm:peer-placeholder-shown:text-[17px] sm:peer-focus:text-sm"
        htmlFor={id}
      >
        {label}
      </label>
      {isPassword ? (
        <button
          aria-label={
            passwordVisible ? t("auth.hidePassword") : t("auth.showPassword")
          }
          className="absolute top-1/2 right-2.5 grid size-10 -translate-y-1/2 place-items-center rounded-[4px] text-muted-foreground transition-colors outline-none hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring"
          onClick={() => setPasswordVisible((visible) => !visible)}
          type="button"
        >
          {passwordVisible ? (
            <EyeOffIcon className="size-5" />
          ) : (
            <EyeIcon className="size-5" />
          )}
        </button>
      ) : null}
    </div>
  )
}

function AuthBrand() {
  return (
    <header className="text-center">
      <div
        aria-label="keen-pbr-sb"
        className="mx-auto flex w-fit origin-center items-baseline leading-none"
        role="img"
        style={{ transform: "scaleX(1.08) scaleY(0.9)" }}
      >
        <span className="text-[28px] font-medium tracking-[0.07em] text-primary sm:text-[36px]">
          KEEN-PBR
        </span>
        <span className="text-[28px] font-medium tracking-[0.07em] text-foreground sm:text-[36px]">
          -SB
        </span>
      </div>
    </header>
  )
}

function AuthPage({ children }: { children: ReactNode }) {
  const { t } = useTranslation()

  return (
    <main className="flex min-h-svh flex-col overflow-x-hidden bg-card">
      <div className="flex flex-1 items-center justify-center px-5 py-10 sm:px-8 sm:py-14">
        <div className="w-full max-w-[600px]">
          <AuthBrand />
          {children}
        </div>
      </div>
      <footer className="flex min-h-24 items-center justify-center bg-primary px-6 py-7 text-center text-base text-primary-foreground sm:min-h-28 sm:text-lg">
        {t("brand.tagline")}
      </footer>
    </main>
  )
}

export function AuthGate({ children }: { children: ReactNode }) {
  const { t } = useTranslation()
  const { language, setLanguage } = useLanguage()
  const [status, setStatus] = useState<AuthStatus | null>(null)
  const [username, setUsername] = useState("admin")
  const [password, setPassword] = useState("")
  const [pending, setPending] = useState(false)
  const [error, setError] = useState("")
  const [showCredentialsHelp, setShowCredentialsHelp] = useState(false)
  const [statusUnavailable, setStatusUnavailable] = useState(false)
  const hasTrustedStatus = useRef(false)

  const refresh = useCallback(async () => {
    try {
      const response = await fetch("/api/auth/status", { cache: "no-store" })
      if (!response.ok) throw new Error(String(response.status))
      const nextStatus = parseAuthStatus(await response.json())
      if (!nextStatus) {
        throw new Error("invalid auth status")
      }
      hasTrustedStatus.current = true
      setStatusUnavailable(false)
      setStatus(nextStatus)
    } catch {
      if (!hasTrustedStatus.current) {
        setStatusUnavailable(true)
      }
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
        const body = await response.json().catch(() => null)
        const endpointUnavailable =
          response.status === 503 &&
          body &&
          typeof body === "object" &&
          "error" in body &&
          body.error === "auth_endpoint_unavailable"
        setError(
          endpointUnavailable
            ? t("auth.unavailable")
            : t("auth.invalidCredentials")
        )
        setShowCredentialsHelp(!endpointUnavailable)
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

  if (!status && !statusUnavailable) {
    return (
      <div className="grid min-h-screen place-items-center">
        <LoaderCircleIcon className="size-7 animate-spin text-muted-foreground" />
      </div>
    )
  }
  if (!status) {
    return (
      <AuthPage>
        <section
          aria-labelledby="auth-unavailable-title"
          className="mx-auto mt-12 max-w-lg text-center"
        >
          <h1
            className="text-2xl font-semibold text-foreground sm:text-3xl"
            id="auth-unavailable-title"
          >
            {t("auth.unavailableTitle")}
          </h1>
          <p className="mt-3 text-base text-muted-foreground">
            {t("auth.unavailable")}
          </p>
          <Button
            className="mt-7 h-14 w-full text-base shadow-none hover:shadow-none active:translate-y-0"
            onClick={() => {
              setStatusUnavailable(false)
              void refresh()
            }}
            type="button"
          >
            {t("auth.retry")}
          </Button>
        </section>
      </AuthPage>
    )
  }
  if (!status.enabled || status.authenticated) return children

  return (
    <AuthPage>
      <form
        aria-label={t("auth.title")}
        className="mx-auto mt-10 w-full max-w-[520px] space-y-5 sm:mt-12"
        onSubmit={submit}
      >
        <AuthInput
          autoComplete="username"
          error={Boolean(error)}
          id="auth-username"
          label={t("auth.username")}
          onChange={(value) => {
            setUsername(value)
            setError("")
          }}
          required
          value={username}
        />
        <AuthInput
          autoComplete="current-password"
          error={Boolean(error)}
          id="auth-password"
          label={t("auth.password")}
          onChange={(value) => {
            setPassword(value)
            setError("")
          }}
          required
          type="password"
          value={password}
        />
        {error ? (
          <p
            aria-live="polite"
            className="-mt-2 px-1 text-sm leading-5 text-destructive"
            role="alert"
          >
            {error}
          </p>
        ) : null}
        <Button
          className="h-14 w-full text-base shadow-none hover:shadow-none active:translate-y-0 sm:text-lg"
          disabled={pending}
          type="submit"
        >
          {pending ? (
            <>
              <LoaderCircleIcon className="size-5 animate-spin" />
              {t("auth.signingIn")}
            </>
          ) : (
            t("auth.signIn")
          )}
        </Button>
        <Select
          items={LANGUAGE_OPTIONS}
          onValueChange={(value) => value && setLanguage(value)}
          value={language}
        >
          <SelectTrigger
            aria-label={t("language.selectorAria")}
            className="h-14 bg-card px-4 text-base shadow-none hover:shadow-none sm:text-[17px]"
          >
            <SelectValue />
          </SelectTrigger>
          <SelectContent
            align="start"
            alignItemWithTrigger={false}
            side="bottom"
          >
            {LANGUAGE_OPTIONS.map((option) => (
              <SelectItem key={option.value} value={option.value}>
                {option.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <div className="flex items-center justify-center gap-4 pt-1 text-sm sm:text-base">
          <button
            className="text-primary underline-offset-4 hover:underline"
            onClick={() => setShowCredentialsHelp((visible) => !visible)}
            type="button"
          >
            {t("auth.cannotSignIn")}
          </button>
          <span aria-hidden="true" className="text-primary">
            |
          </span>
          <a
            className="text-primary underline underline-offset-4"
            href="https://github.com/blindtechnique/keen-pbr-sb/issues"
            rel="noreferrer"
            target="_blank"
          >
            {t("auth.supportCenter")}
          </a>
        </div>
        {showCredentialsHelp ? (
          <p className="px-1 pt-1 text-sm leading-6 text-muted-foreground">
            {t("auth.credentialsHint")}
          </p>
        ) : null}
      </form>
    </AuthPage>
  )
}

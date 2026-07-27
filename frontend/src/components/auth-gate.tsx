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

import logoUrl from "@/assets/logo.png"
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
          "peer h-12 rounded-[4px] bg-card px-3 pt-0.5 text-[15px] shadow-none transition-[border-color,box-shadow] placeholder:text-transparent hover:shadow-none focus-visible:ring-0 lg:h-10 lg:text-sm",
          isPassword && "pr-11"
        )}
        id={id}
        onChange={(event) => onChange(event.target.value)}
        placeholder=" "
        required={required}
        type={resolvedType}
        value={value}
      />
      <label
        className="pointer-events-none absolute top-0 left-2.5 z-10 -translate-y-1/2 bg-card px-1 text-xs leading-4 text-muted-foreground transition-[top,transform,font-size,color,padding,background-color] peer-placeholder-shown:top-1/2 peer-placeholder-shown:-translate-y-1/2 peer-placeholder-shown:bg-transparent peer-placeholder-shown:text-[15px] peer-focus:top-0 peer-focus:-translate-y-1/2 peer-focus:bg-card peer-focus:text-xs peer-focus:text-primary lg:peer-placeholder-shown:text-sm"
        htmlFor={id}
      >
        {label}
      </label>
      {isPassword ? (
        <button
          aria-label={
            passwordVisible ? t("auth.hidePassword") : t("auth.showPassword")
          }
          className="absolute top-1/2 right-2 grid size-9 -translate-y-1/2 place-items-center rounded-[4px] text-muted-foreground transition-colors outline-none hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring"
          onClick={() => setPasswordVisible((visible) => !visible)}
          type="button"
        >
          {passwordVisible ? (
            <EyeOffIcon className="size-4.5" />
          ) : (
            <EyeIcon className="size-4.5" />
          )}
        </button>
      ) : null}
    </div>
  )
}

function AuthBrand({
  inverted = false,
  showLogo = false,
}: {
  readonly inverted?: boolean
  readonly showLogo?: boolean
}) {
  return (
    <header className="flex flex-col items-center text-center">
      {showLogo ? (
        <img
          alt=""
          aria-hidden="true"
          className="mb-7 size-24 rounded-2xl object-contain"
          src={logoUrl}
        />
      ) : null}
      <div
        aria-label="keen-pbr-sb"
        className="mx-auto flex w-fit origin-center items-baseline leading-none"
        role="img"
        style={{ transform: "scaleX(1.18) scaleY(0.82)" }}
      >
        <span
          className={cn(
            "text-[28px] tracking-[0.07em] sm:text-[36px]",
            inverted
              ? "font-normal text-primary-foreground"
              : "font-medium text-primary"
          )}
        >
          KEEN-PBR
        </span>
        <span
          className={cn(
            "text-[28px] tracking-[0.07em] sm:text-[36px]",
            inverted
              ? "font-normal text-primary-foreground"
              : "font-medium text-foreground"
          )}
        >
          -SB
        </span>
      </div>
    </header>
  )
}

function AuthPage({ children }: { children: ReactNode }) {
  const { t } = useTranslation()

  return (
    <main className="min-h-svh overflow-x-hidden bg-card lg:grid lg:grid-cols-2">
      <section className="flex min-h-svh items-center justify-center px-5 py-8 sm:px-8">
        <div className="w-full max-w-[382px]">
          <div className="mb-10 lg:hidden">
            <AuthBrand />
          </div>
          {children}
        </div>
      </section>
      <aside className="relative hidden min-h-svh overflow-hidden bg-primary text-primary-foreground lg:block">
        <div className="absolute top-[42%] right-0 left-0 -translate-y-1/2">
          <AuthBrand inverted showLogo />
        </div>
        <div className="absolute right-0 bottom-[27%] left-0 px-8 text-center text-sm font-medium">
          <a
            className="text-inherit no-underline outline-none hover:text-inherit hover:no-underline focus-visible:ring-2 focus-visible:ring-primary-foreground"
            href="https://github.com/blindtechnique/keen-pbr-sb"
            rel="noreferrer"
            target="_blank"
          >
            {t("auth.otherManagement")}
          </a>
        </div>
      </aside>
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
          className="w-full rounded-[6px] px-1 py-8 text-center lg:min-h-[432px] lg:border lg:border-input lg:px-10 lg:py-10"
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
        className="w-full space-y-4 rounded-[6px] px-1 py-1 lg:min-h-[432px] lg:border lg:border-input lg:px-10 lg:py-10"
        onSubmit={submit}
      >
        <h1 className="mx-auto mb-7 max-w-[250px] text-center text-[28px] leading-9 font-semibold text-foreground">
          {t("auth.title")}
        </h1>
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
          className="h-12 w-full text-base shadow-none hover:shadow-none active:translate-y-0 lg:h-10 lg:text-sm"
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
            className="h-12 bg-card px-3 text-[15px] shadow-none hover:shadow-none lg:h-10 lg:text-sm"
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
        <div className="flex items-center justify-center gap-3 pt-0.5 text-sm">
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

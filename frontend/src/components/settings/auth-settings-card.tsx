import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { useEffect, useState } from "react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"

type AuthStatus = {
  enabled: boolean
  provider?: "local" | "keenetic"
  keenetic_endpoint?: string
  authenticated: boolean
}

/**
 * Lets the login mode be switched from the interface. Router credentials are
 * verified before the change is stored, so a typo cannot lock anyone out.
 */
export function AuthSettingsCard() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()

  const statusQuery = useQuery<AuthStatus>({
    queryKey: ["auth-status"],
    queryFn: async () => {
      const response = await fetch("/api/auth/status", { cache: "no-store" })
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      return response.json()
    },
  })

  const [enabled, setEnabled] = useState(true)
  const [provider, setProvider] = useState<"local" | "keenetic">("keenetic")
  const [endpoint, setEndpoint] = useState("127.0.0.1:80")
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")

  useEffect(() => {
    const status = statusQuery.data
    if (!status) return
    setEnabled(status.enabled)
    setProvider(status.provider === "local" ? "local" : "keenetic")
    setEndpoint(status.keenetic_endpoint || "127.0.0.1:80")
  }, [statusQuery.data])

  const saveMutation = useMutation({
    mutationFn: async () => {
      const response = await fetch("/api/auth/settings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          enabled,
          provider,
          keenetic_endpoint: endpoint,
          username,
          password,
        }),
      })
      const data = await response.json().catch(() => ({}))
      if (!response.ok) {
        throw new Error(data.error || `HTTP ${response.status}`)
      }
      return data
    },
    onSuccess: async () => {
      setPassword("")
      await queryClient.invalidateQueries({ queryKey: ["auth-status"] })
      toast.success(t("pages.settings.auth.saved"))
    },
    onError: (error: Error) =>
      toast.error(error.message, { richColors: true }),
  })

  const needsCredentials = provider === "local" && enabled

  return (
    <Card size="sm">
      <CardHeader>
        <CardTitle>{t("pages.settings.auth.title")}</CardTitle>
        <CardDescription>
          {t("pages.settings.auth.description")}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-center gap-3">
          <Switch
            checked={enabled}
            id="auth-enabled"
            onCheckedChange={setEnabled}
          />
          <Label className="cursor-pointer" htmlFor="auth-enabled">
            {t("pages.settings.auth.enabled")}
          </Label>
        </div>

        {enabled ? (
          <>
            <div className="grid gap-1.5">
              <Label>{t("pages.settings.auth.provider")}</Label>
              <Select
                onValueChange={(value) =>
                  setProvider(value === "local" ? "local" : "keenetic")
                }
                value={provider}
              >
                <SelectTrigger>
                  <SelectValue>
                    {(selected) =>
                      selected === "local"
                        ? t("pages.settings.auth.providerLocal")
                        : t("pages.settings.auth.providerRouter")
                    }
                  </SelectValue>
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    <SelectItem value="keenetic">
                      {t("pages.settings.auth.providerRouter")}
                    </SelectItem>
                    <SelectItem value="local">
                      {t("pages.settings.auth.providerLocal")}
                    </SelectItem>
                  </SelectGroup>
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                {provider === "keenetic"
                  ? t("pages.settings.auth.providerRouterHint")
                  : t("pages.settings.auth.providerLocalHint")}
              </p>
            </div>

            {provider === "keenetic" ? (
              <div className="grid gap-1.5">
                <Label htmlFor="auth-endpoint">
                  {t("pages.settings.auth.endpoint")}
                </Label>
                <Input
                  id="auth-endpoint"
                  onChange={(event) => setEndpoint(event.target.value)}
                  placeholder="127.0.0.1:80"
                  value={endpoint}
                />
              </div>
            ) : null}

            <div className="grid gap-1.5 sm:grid-cols-2 sm:gap-3">
              <div className="grid gap-1.5">
                <Label htmlFor="auth-username">
                  {t("pages.settings.auth.username")}
                </Label>
                <Input
                  autoComplete="username"
                  id="auth-username"
                  onChange={(event) => setUsername(event.target.value)}
                  value={username}
                />
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor="auth-password">
                  {t("pages.settings.auth.password")}
                </Label>
                <Input
                  autoComplete="new-password"
                  id="auth-password"
                  onChange={(event) => setPassword(event.target.value)}
                  type="password"
                  value={password}
                />
              </div>
            </div>

            <p className="text-xs text-muted-foreground">
              {provider === "keenetic"
                ? t("pages.settings.auth.verifyHint")
                : t("pages.settings.auth.localStoreHint")}
            </p>
          </>
        ) : null}

        <div className="flex justify-end">
          <Button
            disabled={
              saveMutation.isPending ||
              (needsCredentials && (!username || !password))
            }
            onClick={() => saveMutation.mutate()}
          >
            {saveMutation.isPending
              ? t("common.saving")
              : t("pages.settings.auth.save")}
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}

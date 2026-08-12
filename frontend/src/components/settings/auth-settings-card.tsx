import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import {
  forwardRef,
  useImperativeHandle,
  useState,
  type ForwardedRef,
} from "react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
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
import {
  authEndpointModeLabelKey,
  type KeeneticEndpointMode,
} from "@/lib/auth-status"
import { fetchWithStepUp } from "@/lib/step-up"
import type {
  SettingsSectionController,
  SettingsSectionState,
} from "@/components/settings/settings-section-control"

type AuthStatus = {
  enabled: boolean
  provider?: "local" | "keenetic"
  keenetic_endpoint?: string
  keenetic_endpoint_mode?: KeeneticEndpointMode
  keenetic_endpoint_source?: "ndms" | "fallback"
  authenticated: boolean
}

type RemoteAccessAuthSafety = {
  keenetic_auth_switch_allowed?: boolean
}

type AuthDraft = {
  enabled: boolean
  provider: "local" | "keenetic"
  endpointMode: KeeneticEndpointMode
  endpoint: string
}

/**
 * Lets the login mode be switched from the interface. Router credentials are
 * verified before the change is stored, so a typo cannot lock anyone out.
 */
export const AuthSettingsCard = forwardRef(AuthSettingsCardInner)

function AuthSettingsCardInner(
  {
    onStateChange,
  }: {
    onStateChange: (state: SettingsSectionState) => void
  },
  ref: ForwardedRef<SettingsSectionController>
) {
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
  const remoteAccessQuery = useQuery<RemoteAccessAuthSafety>({
    queryKey: ["remote-access"],
    queryFn: async () => {
      const response = await fetch("/api/system/remote-access", {
        cache: "no-store",
      })
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      return response.json()
    },
  })

  const [draft, setDraft] = useState<Partial<AuthDraft>>({})
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")

  const enabled = draft.enabled ?? statusQuery.data?.enabled ?? true
  const provider =
    draft.provider ??
    (statusQuery.data?.provider === "local" ? "local" : "keenetic")
  const endpoint = draft.endpoint ?? statusQuery.data?.keenetic_endpoint ?? ""
  const endpointMode =
    draft.endpointMode ?? statusQuery.data?.keenetic_endpoint_mode ?? "auto"
  const keeneticAuthSwitchAllowed =
    remoteAccessQuery.data?.keenetic_auth_switch_allowed === true

  const saveMutation = useMutation({
    mutationFn: async () => {
      if (enabled && provider === "keenetic" && !keeneticAuthSwitchAllowed) {
        throw new Error(t("pages.settings.auth.remoteAccessConflict"))
      }
      const response = await fetchWithStepUp("/api/auth/settings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          enabled,
          provider,
          keenetic_endpoint_mode: endpointMode,
          keenetic_endpoint: endpoint,
          username,
          password,
        }),
      })
      const data = await response.json().catch(() => ({}))
      if (!response.ok) {
        if (data.error === "remote_access_incompatible_with_keenetic_auth") {
          throw new Error(t("pages.settings.auth.remoteAccessConflict"))
        }
        if (
          data.error === "system_auth_capability_not_usable" ||
          data.error === "system_auth_requires_enabled_verification"
        ) {
          throw new Error(t("pages.settings.auth.systemAuthUnavailable"))
        }
        throw new Error(data.error || `HTTP ${response.status}`)
      }
      return data
    },
    onSuccess: async () => {
      setPassword("")
      await queryClient.invalidateQueries({ queryKey: ["auth-status"] })
      setDraft({})
      onStateChange({ dirty: false, valid: true })
      toast.success(t("pages.settings.auth.saved"))
    },
    onError: (error: Error) => toast.error(error.message, { richColors: true }),
  })

  const getSectionState = (
    nextDraft = draft,
    nextUsername = username,
    nextPassword = password
  ): SettingsSectionState => {
    const nextEnabled = nextDraft.enabled ?? statusQuery.data?.enabled ?? true
    const nextProvider =
      nextDraft.provider ??
      (statusQuery.data?.provider === "local" ? "local" : "keenetic")
    const dirty =
      Object.keys(nextDraft).length > 0 ||
      nextUsername.length > 0 ||
      nextPassword.length > 0
    const credentialsRequired =
      nextEnabled &&
      (nextProvider === "local" ||
        (nextProvider === "keenetic" &&
          (!statusQuery.data?.enabled ||
            statusQuery.data?.provider !== "keenetic")))
    const nextEndpointMode =
      nextDraft.endpointMode ??
      statusQuery.data?.keenetic_endpoint_mode ??
      "auto"
    const manualEndpointMissing =
      nextProvider === "keenetic" &&
      nextEnabled &&
      nextEndpointMode === "manual" &&
      (nextDraft.endpoint ?? endpoint).trim().length === 0
    const remoteAccessConflict =
      nextEnabled && nextProvider === "keenetic" && !keeneticAuthSwitchAllowed
    return {
      dirty,
      valid:
        !dirty ||
        ((!credentialsRequired ||
          (nextUsername.length > 0 && nextPassword.length > 0)) &&
          !manualEndpointMissing &&
          !remoteAccessConflict),
    }
  }

  const updateDraft = (patch: Partial<AuthDraft>) => {
    const nextDraft = { ...draft, ...patch }
    setDraft(nextDraft)
    onStateChange(getSectionState(nextDraft))
  }

  const updateUsername = (nextUsername: string) => {
    setUsername(nextUsername)
    onStateChange(getSectionState(draft, nextUsername, password))
  }

  const updatePassword = (nextPassword: string) => {
    setPassword(nextPassword)
    onStateChange(getSectionState(draft, username, nextPassword))
  }

  useImperativeHandle(ref, () => ({
    reset: () => {
      setDraft({})
      setUsername("")
      setPassword("")
      onStateChange({ dirty: false, valid: true })
    },
    save: async () => {
      const state = getSectionState()
      if (!state.dirty) {
        return
      }
      if (!state.valid) {
        if (enabled && provider === "keenetic" && !keeneticAuthSwitchAllowed) {
          throw new Error(t("pages.settings.auth.remoteAccessConflict"))
        }
        throw new Error(t("pages.settings.auth.verifyHint"))
      }
      await saveMutation.mutateAsync()
    },
  }))

  return (
    <Card size="sm">
      <CardHeader>
        <CardTitle>{t("pages.settings.auth.title")}</CardTitle>
        <CardDescription className="max-w-[480px]">
          {t("pages.settings.auth.description")}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-center gap-3">
          <Switch
            checked={enabled}
            id="auth-enabled"
            onCheckedChange={(nextEnabled) =>
              updateDraft({ enabled: nextEnabled })
            }
          />
          <Label className="cursor-pointer" htmlFor="auth-enabled">
            {t("pages.settings.auth.enabled")}
          </Label>
        </div>

        {enabled ? (
          <>
            <div className="grid max-w-[480px] gap-1.5">
              <Label>{t("pages.settings.auth.provider")}</Label>
              <Select
                onValueChange={(value) =>
                  updateDraft({
                    provider: value === "local" ? "local" : "keenetic",
                  })
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
                    <SelectItem
                      disabled={
                        !keeneticAuthSwitchAllowed && provider !== "keenetic"
                      }
                      value="keenetic"
                    >
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
                  ? keeneticAuthSwitchAllowed
                    ? t("pages.settings.auth.providerRouterHint")
                    : t("pages.settings.auth.remoteAccessConflict")
                  : t("pages.settings.auth.providerLocalHint")}
              </p>
            </div>

            {provider === "keenetic" ? (
              <div className="grid max-w-[480px] gap-3">
                <div className="grid gap-1.5">
                  <Label>{t("pages.settings.auth.endpointMode")}</Label>
                  <Select
                    onValueChange={(value) =>
                      updateDraft({
                        endpointMode: value === "manual" ? "manual" : "auto",
                      })
                    }
                    value={endpointMode}
                  >
                    <SelectTrigger>
                      <SelectValue>
                        {(selected) =>
                          t(
                            authEndpointModeLabelKey(
                              selected === "manual" ? "manual" : "auto"
                            )
                          )
                        }
                      </SelectValue>
                    </SelectTrigger>
                    <SelectContent>
                      <SelectGroup>
                        <SelectItem value="auto">
                          {t(authEndpointModeLabelKey("auto"))}
                        </SelectItem>
                        <SelectItem value="manual">
                          {t(authEndpointModeLabelKey("manual"))}
                        </SelectItem>
                      </SelectGroup>
                    </SelectContent>
                  </Select>
                  <p className="text-xs text-muted-foreground">
                    {endpointMode === "auto"
                      ? t("pages.settings.auth.endpointModeAutoHint", {
                          endpoint:
                            statusQuery.data?.keenetic_endpoint ??
                            t("pages.settings.auth.endpointUnavailable"),
                        })
                      : t("pages.settings.auth.endpointModeManualHint")}
                  </p>
                </div>

                {endpointMode === "manual" ? (
                  <div className="grid gap-1.5">
                    <Label htmlFor="auth-endpoint">
                      {t("pages.settings.auth.endpoint")}
                    </Label>
                    <Input
                      id="auth-endpoint"
                      onChange={(event) =>
                        updateDraft({ endpoint: event.target.value })
                      }
                      placeholder="192.168.1.1:80"
                      value={endpoint}
                    />
                  </div>
                ) : (
                  <details className="text-sm">
                    <summary className="cursor-pointer text-muted-foreground">
                      {t("pages.settings.auth.endpointFallbackAdvanced")}
                    </summary>
                    <div className="mt-3 grid gap-1.5">
                      <Label htmlFor="auth-endpoint-fallback">
                        {t("pages.settings.auth.endpointFallback")}
                      </Label>
                      <Input
                        id="auth-endpoint-fallback"
                        onChange={(event) =>
                          updateDraft({ endpoint: event.target.value })
                        }
                        placeholder="192.168.1.1:80"
                        value={endpoint}
                      />
                      <p className="text-xs text-muted-foreground">
                        {t("pages.settings.auth.endpointFallbackHint")}
                      </p>
                    </div>
                  </details>
                )}
              </div>
            ) : null}

            <div className="grid max-w-[480px] gap-1.5 sm:grid-cols-2 sm:gap-3">
              <div className="grid gap-1.5">
                <Label htmlFor="auth-username">
                  {t("pages.settings.auth.username")}
                </Label>
                <Input
                  autoComplete="username"
                  id="auth-username"
                  onChange={(event) => updateUsername(event.target.value)}
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
                  onChange={(event) => updatePassword(event.target.value)}
                  type="password"
                  value={password}
                />
              </div>
            </div>

            <p className="max-w-[480px] text-xs text-muted-foreground">
              {provider === "keenetic"
                ? t("pages.settings.auth.verifyHint")
                : t("pages.settings.auth.localStoreHint")}
            </p>
          </>
        ) : null}
      </CardContent>
    </Card>
  )
}

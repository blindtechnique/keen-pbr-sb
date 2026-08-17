import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import {
  forwardRef,
  useImperativeHandle,
  useState,
  type ForwardedRef,
} from "react"
import { AlertTriangleIcon } from "lucide-react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"

import { Alert, AlertDescription } from "@/components/ui/alert"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"
import type {
  SettingsSectionController,
  SettingsSectionState,
} from "@/components/settings/settings-section-control"
import { fetchWithStepUp } from "@/lib/step-up"

type RemoteAccess = {
  enabled: boolean
  port: number
  login_required: boolean
  internal_port: number
  listen?: string
  listen_reachable?: boolean
  auth_provider?: "local" | "keenetic" | "unavailable"
  blocked_reason?:
    | "auth_state_unavailable"
    | "login_disabled"
    | "keenetic_auth_plaintext_wan"
    | "listen_loopback"
    | null
  custom_port_supported?: boolean
  supported_port?: number
}

type RemoteAccessDraft = {
  enabled: boolean
  port: string
}

/**
 * Publishing the panel is off by default and refuses to turn on while login is
 * disabled: an unauthenticated control panel on the open internet is not
 * something a single switch should be able to produce.
 */
export const RemoteAccessCard = forwardRef(RemoteAccessCardInner)

function RemoteAccessCardInner(
  {
    onStateChange,
  }: {
    onStateChange: (state: SettingsSectionState) => void
  },
  ref: ForwardedRef<SettingsSectionController>
) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()

  const query = useQuery<RemoteAccess>({
    queryKey: ["remote-access"],
    queryFn: async () => {
      const response = await fetch("/api/system/remote-access")
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      return response.json()
    },
  })

  const [draft, setDraft] = useState<Partial<RemoteAccessDraft>>({})
  const enabled = draft.enabled ?? query.data?.enabled ?? false
  const port = draft.port ?? String(query.data?.port ?? 12121)

  const saveMutation = useMutation({
    mutationFn: async () => {
      const response = await fetchWithStepUp("/api/system/remote-access", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled, port: Number(port) }),
      })
      const data = await response.json().catch(() => ({}))
      if (!response.ok || data.error) {
        if (data.error === "login_disabled") {
          throw new Error(t("pages.settings.remoteAccess.loginDisabled"))
        }
        if (data.error === "listen_loopback") {
          throw new Error(
            t("pages.settings.remoteAccess.listenLoopback", {
              listen: data.listen,
            })
          )
        }
        if (data.error === "keenetic_auth_plaintext_wan") {
          throw new Error(t("pages.settings.remoteAccess.keeneticAuthBlocked"))
        }
        if (data.error === "custom_port_not_supported_safely") {
          throw new Error(
            t("pages.settings.remoteAccess.fixedPortHint", {
              port: data.supported_port ?? 12121,
            })
          )
        }
        throw new Error(data.error || `HTTP ${response.status}`)
      }
      return data
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["remote-access"] })
      setDraft({})
      onStateChange({ dirty: false, valid: true })
      toast.success(t("pages.settings.remoteAccess.saved"))
    },
    onError: (error: Error) => toast.error(error.message, { richColors: true }),
  })

  const loginRequired = query.data?.login_required ?? false
  const keeneticAuth = query.data?.auth_provider === "keenetic"
  // A panel bound to loopback cannot be published at all; from outside that
  // looks exactly like a blocked port, so it has to be said here.
  const listenReachable = query.data?.listen_reachable ?? true
  const blocked = !loginRequired || !listenReachable || keeneticAuth
  const getSectionState = (nextDraft = draft): SettingsSectionState => {
    const nextPort = Number(nextDraft.port ?? port)
    const nextEnabled = nextDraft.enabled ?? enabled
    const dirty = Object.keys(nextDraft).length > 0
    return {
      dirty,
      valid:
        !dirty ||
        !nextEnabled ||
        (!blocked &&
          Number.isInteger(nextPort) &&
          nextPort === (query.data?.supported_port ?? 12121)),
    }
  }

  const updateDraft = (patch: Partial<RemoteAccessDraft>) => {
    const nextDraft = { ...draft, ...patch }
    setDraft(nextDraft)
    onStateChange(getSectionState(nextDraft))
  }

  useImperativeHandle(ref, () => ({
    reset: () => {
      setDraft({})
      onStateChange({ dirty: false, valid: true })
    },
    save: async () => {
      const state = getSectionState()
      if (!state.dirty) {
        return
      }
      if (!state.valid) {
        throw new Error(
          t("pages.settings.remoteAccess.fixedPortHint", {
            port: query.data?.supported_port ?? 12121,
          })
        )
      }
      await saveMutation.mutateAsync()
    },
  }))

  return (
    <Card size="sm">
      <CardHeader>
        <CardTitle>{t("pages.settings.remoteAccess.title")}</CardTitle>
        <CardDescription className="max-w-[480px]">
          {t("pages.settings.remoteAccess.description")}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {!loginRequired ? (
          <Alert className="max-w-[480px] border-warning/40 bg-warning/10">
            <AlertTriangleIcon className="size-4 text-warning-foreground" />
            <AlertDescription>
              {t("pages.settings.remoteAccess.loginDisabled")}
            </AlertDescription>
          </Alert>
        ) : null}

        {!listenReachable ? (
          <Alert className="max-w-[480px] border-warning/40 bg-warning/10">
            <AlertTriangleIcon className="size-4 text-warning-foreground" />
            <AlertDescription>
              {t("pages.settings.remoteAccess.listenLoopback", {
                listen: query.data?.listen ?? "",
              })}
            </AlertDescription>
          </Alert>
        ) : null}

        {keeneticAuth ? (
          <Alert className="max-w-[480px] border-warning/40 bg-warning/10">
            <AlertTriangleIcon className="size-4 text-warning-foreground" />
            <AlertDescription>
              {t("pages.settings.remoteAccess.keeneticAuthBlocked")}
            </AlertDescription>
          </Alert>
        ) : null}

        <div className="flex items-center gap-3">
          <Switch
            checked={enabled}
            disabled={blocked && !enabled}
            id="remote-access-enabled"
            onCheckedChange={(nextEnabled) =>
              updateDraft({
                enabled: nextEnabled,
                ...(nextEnabled
                  ? { port: String(query.data?.supported_port ?? 12121) }
                  : {}),
              })
            }
          />
          <Label className="cursor-pointer" htmlFor="remote-access-enabled">
            {t("pages.settings.remoteAccess.enabled")}
          </Label>
        </div>

        {enabled ? (
          <>
            <Alert className="max-w-[480px] border-destructive/40 bg-destructive/5">
              <AlertTriangleIcon className="size-4 text-destructive" />
              <AlertDescription>
                {t("pages.settings.remoteAccess.warning")}
              </AlertDescription>
            </Alert>

            <div className="grid gap-1.5 sm:max-w-[12rem]">
              <Label htmlFor="remote-access-port">
                {t("pages.settings.remoteAccess.port")}
              </Label>
              <Input
                disabled
                id="remote-access-port"
                inputMode="numeric"
                onChange={(event) => updateDraft({ port: event.target.value })}
                value={port}
              />
              <p className="text-xs text-muted-foreground">
                {t("pages.settings.remoteAccess.fixedPortHint", {
                  port: query.data?.supported_port ?? 12121,
                })}
              </p>
            </div>
          </>
        ) : null}
      </CardContent>
    </Card>
  )
}

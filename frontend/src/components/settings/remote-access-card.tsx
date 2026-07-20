import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { useEffect, useState } from "react"
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
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"

type RemoteAccess = {
  enabled: boolean
  port: number
  login_required: boolean
  internal_port: number
}

/**
 * Publishing the panel is off by default and refuses to turn on while login is
 * disabled: an unauthenticated control panel on the open internet is not
 * something a single switch should be able to produce.
 */
export function RemoteAccessCard() {
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

  const [enabled, setEnabled] = useState(false)
  const [port, setPort] = useState("12121")

  useEffect(() => {
    if (!query.data) return
    setEnabled(query.data.enabled)
    setPort(String(query.data.port))
  }, [query.data])

  const saveMutation = useMutation({
    mutationFn: async () => {
      const response = await fetch("/api/system/remote-access", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled, port: Number(port) }),
      })
      const data = await response.json().catch(() => ({}))
      if (!response.ok || data.error) {
        throw new Error(
          data.error === "login_disabled"
            ? t("pages.settings.remoteAccess.loginDisabled")
            : data.error || `HTTP ${response.status}`
        )
      }
      return data
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["remote-access"] })
      toast.success(t("pages.settings.remoteAccess.saved"))
    },
    onError: (error: Error) => toast.error(error.message, { richColors: true }),
  })

  const loginRequired = query.data?.login_required ?? false

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("pages.settings.remoteAccess.title")}</CardTitle>
        <CardDescription>
          {t("pages.settings.remoteAccess.description")}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {!loginRequired ? (
          <Alert className="border-warning/40 bg-warning/10">
            <AlertTriangleIcon className="size-4 text-warning" />
            <AlertDescription>
              {t("pages.settings.remoteAccess.loginDisabled")}
            </AlertDescription>
          </Alert>
        ) : null}

        <div className="flex items-center gap-3">
          <Switch
            checked={enabled}
            disabled={!loginRequired}
            id="remote-access-enabled"
            onCheckedChange={setEnabled}
          />
          <Label className="cursor-pointer" htmlFor="remote-access-enabled">
            {t("pages.settings.remoteAccess.enabled")}
          </Label>
        </div>

        {enabled ? (
          <>
            <Alert className="border-destructive/40 bg-destructive/5">
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
                id="remote-access-port"
                inputMode="numeric"
                onChange={(event) => setPort(event.target.value)}
                value={port}
              />
              <p className="text-xs text-muted-foreground">
                {t("pages.settings.remoteAccess.portHint")}
              </p>
            </div>
          </>
        ) : null}

        <div className="flex justify-end">
          <Button
            disabled={saveMutation.isPending || !loginRequired}
            onClick={() => saveMutation.mutate()}
          >
            {saveMutation.isPending
              ? t("common.saving")
              : t("pages.settings.remoteAccess.save")}
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}

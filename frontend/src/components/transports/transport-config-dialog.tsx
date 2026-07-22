import { useMemo, useState, type FormEvent, type ReactNode } from "react"
import { useTranslation } from "react-i18next"

import { TransportSpecType, type TransportSpec } from "@/api/generated/model"
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
import { Switch } from "@/components/ui/switch"
import { Textarea } from "@/components/ui/textarea"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { countryOptions } from "@/data/countries"

type Props = {
  initial?: TransportSpec
  isPending: boolean
  onOpenChange: (open: boolean) => void
  onSubmit: (spec: TransportSpec, options: { createOutbound: boolean }) => void
  open: boolean
  singBoxAvailable?: boolean
}

type SourceMode = "link" | "json"

const emptySpec = (): TransportSpec => ({
  tag: "",
  type: TransportSpecType.native,
  interface: "",
  auto_start: false,
  geo_mode: "disabled",
})

export function TransportConfigDialog({
  initial,
  isPending,
  onOpenChange,
  onSubmit,
  open,
  singBoxAvailable = true,
}: Props) {
  const { t, i18n } = useTranslation()
  const [spec, setSpec] = useState<TransportSpec>(() =>
    initial ? structuredClone(initial) : emptySpec()
  )
  const [sourceMode, setSourceMode] = useState<SourceMode>("link")
  // A transport only becomes a route once an interface outbound points at it,
  // so offer that step right here instead of sending people to another page.
  const [createOutbound, setCreateOutbound] = useState(!initial)
  const countries = useMemo(
    () => countryOptions(i18n.resolvedLanguage ?? i18n.language ?? "ru"),
    [i18n.language, i18n.resolvedLanguage]
  )

  const isSingBox = spec.type !== TransportSpecType.native
  const submit = (event: FormEvent) => {
    event.preventDefault()
    const normalizedSpec: TransportSpec = {
      ...spec,
      geo_mode: spec.geo_mode ?? "disabled",
      country_code:
        spec.geo_mode === "manual"
          ? spec.country_code?.trim().toUpperCase()
          : undefined,
      country: spec.geo_mode === "manual" ? spec.country?.trim() : undefined,
    }
    if (!isSingBox) {
      onSubmit(
        {
          ...normalizedSpec,
          link: undefined,
          outbound_json: undefined,
          mtu: undefined,
          vless: undefined,
        },
        { createOutbound: createOutbound && !initial }
      )
      return
    }
    onSubmit(
      {
        ...normalizedSpec,
        link: sourceMode === "link" ? spec.link : undefined,
        outbound_json: sourceMode === "json" ? spec.outbound_json : undefined,
        bootstrap_dns: spec.bootstrap_dns?.filter(Boolean),
        vless: undefined,
      },
      { createOutbound: createOutbound && !initial }
    )
  }

  return (
    <Dialog onOpenChange={onOpenChange} open={open}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>
            {initial
              ? t("transports.form.editTitle")
              : t("transports.form.createTitle")}
          </DialogTitle>
          <DialogDescription>
            {t("transports.form.description")}
          </DialogDescription>
        </DialogHeader>
        <form className="grid gap-4" onSubmit={submit}>
          <Field label={t("transports.form.tag")}>
            <Input
              aria-describedby="transport-tag-hint"
              disabled={Boolean(initial)}
              maxLength={24}
              onChange={(event) =>
                setSpec({ ...spec, tag: event.target.value })
              }
              pattern="[a-z][a-z0-9_]{0,23}"
              placeholder="my_transport"
              required
              title={t("transports.form.tagHint")}
              value={spec.tag}
            />
            <p
              className="text-xs text-muted-foreground"
              id="transport-tag-hint"
            >
              {t("transports.form.tagHint")}
            </p>
          </Field>
          <Field label={t("transports.form.type")}>
            <select
              className="h-9 rounded-md border bg-background px-3"
              disabled={Boolean(initial)}
              onChange={(event) =>
                setSpec({
                  ...spec,
                  type: event.target.value as TransportSpec["type"],
                })
              }
              value={spec.type}
            >
              <option value={TransportSpecType.native}>
                {t("transports.form.native")}
              </option>
              <option value={TransportSpecType["sing-box"]}>
                {t("transports.form.singBox")}
              </option>
              {spec.type === TransportSpecType["sing-box-vless-reality"] ? (
                <option value={TransportSpecType["sing-box-vless-reality"]}>
                  {t("transports.form.singBoxLegacy")}
                </option>
              ) : null}
            </select>
          </Field>
          <Field label={t("transports.form.interface")}>
            <Input
              maxLength={15}
              onChange={(event) =>
                setSpec({ ...spec, interface: event.target.value })
              }
              pattern="[A-Za-z0-9_.-]{1,15}"
              placeholder="kpbr0"
              required
              value={spec.interface}
            />
          </Field>
          <div className="flex items-center justify-between rounded-md border p-3">
            <Label htmlFor="transport-auto-start">
              {t("transports.form.autoStart")}
            </Label>
            <Switch
              checked={spec.auto_start ?? false}
              id="transport-auto-start"
              onCheckedChange={(checked) =>
                setSpec({ ...spec, auto_start: checked })
              }
            />
          </div>
          <Field label={t("transports.form.countryDisplay")}>
            <div className="grid gap-2 rounded-md border p-3">
              {(["disabled", "manual", "auto"] as const).map((mode) => (
                <label
                  className="flex cursor-pointer items-start gap-3 rounded-md border border-transparent p-2 has-[:checked]:border-primary has-[:checked]:bg-primary/10"
                  key={mode}
                >
                  <input
                    checked={(spec.geo_mode ?? "disabled") === mode}
                    className="mt-1 accent-primary"
                    name="transport-geo-mode"
                    onChange={() => setSpec({ ...spec, geo_mode: mode })}
                    type="radio"
                  />
                  <span className="grid gap-0.5">
                    <span className="text-sm font-medium">
                      {t(`transports.form.geo.${mode}`)}
                    </span>
                    {mode === "auto" ? (
                      <span className="text-xs text-amber-700 dark:text-amber-300">
                        {t("transports.form.geo.autoWarning")}
                      </span>
                    ) : null}
                  </span>
                </label>
              ))}
              {spec.geo_mode === "manual" ? (
                <select
                  className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"
                  onChange={(event) => {
                    const selected = countries.find(
                      (country) => country.code === event.target.value
                    )
                    setSpec({
                      ...spec,
                      country_code: selected?.code,
                      country: selected?.name,
                    })
                  }}
                  required
                  value={spec.country_code?.toUpperCase() ?? ""}
                >
                  <option disabled value="">
                    {t("transports.form.geo.countryPlaceholder")}
                  </option>
                  {countries.map((country) => (
                    <option key={country.code} value={country.code}>
                      {country.flag} {country.name} ({country.code})
                    </option>
                  ))}
                </select>
              ) : null}
            </div>
          </Field>
          {!initial ? (
            <div className="flex items-center justify-between rounded-md border p-3">
              <div className="min-w-0 pr-3">
                <Label htmlFor="transport-create-outbound">
                  {t("transports.form.createOutbound")}
                </Label>
                <p className="mt-1 text-xs text-muted-foreground">
                  {t("transports.form.createOutboundHint")}
                </p>
              </div>
              <Switch
                checked={createOutbound}
                id="transport-create-outbound"
                onCheckedChange={setCreateOutbound}
              />
            </div>
          ) : null}

          {isSingBox ? (
            <div className="grid gap-4 rounded-lg border p-4">
              {!singBoxAvailable ? (
                <Alert variant="destructive">
                  <AlertTitle>
                    {t("transports.singBoxMissing.title")}
                  </AlertTitle>
                  <AlertDescription className="space-y-2">
                    <p>{t("transports.singBoxMissing.description")}</p>
                    <code className="block overflow-x-auto rounded bg-muted p-2 text-xs text-foreground">
                      sh -c &quot;$(curl -fsSL
                      https://raw.githubusercontent.com/blindtechnique/keen-pbr-sb/main/install.sh)&quot;
                    </code>
                  </AlertDescription>
                </Alert>
              ) : null}
              <div className="grid grid-cols-2 gap-2">
                <Button
                  type="button"
                  variant={sourceMode === "link" ? "default" : "outline"}
                  onClick={() => setSourceMode("link")}
                >
                  {t("transports.form.shareLink")}
                </Button>
                <Button
                  type="button"
                  variant={sourceMode === "json" ? "default" : "outline"}
                  onClick={() => setSourceMode("json")}
                >
                  {t("transports.form.outboundJson")}
                </Button>
              </div>
              {sourceMode === "link" ? (
                <Field label={t("transports.form.shareLink")}>
                  <Textarea
                    className="min-h-28 font-mono text-xs"
                    onChange={(event) =>
                      setSpec({ ...spec, link: event.target.value })
                    }
                    placeholder={
                      initial
                        ? t("transports.form.keepConnection")
                        : "vless://…  vmess://…  trojan://…  ss://…  hy2://…  tuic://…"
                    }
                    required={!initial}
                    value={spec.link ?? ""}
                  />
                  <p className="text-xs text-muted-foreground">
                    {t("transports.form.shareLinkHint")}
                  </p>
                </Field>
              ) : (
                <Field label={t("transports.form.outboundJson")}>
                  <Textarea
                    className="min-h-48 font-mono text-xs"
                    onChange={(event) =>
                      setSpec({ ...spec, outbound_json: event.target.value })
                    }
                    placeholder={
                      initial
                        ? t("transports.form.keepConnection")
                        : '{\n  "type": "ssh",\n  "server": "example.com",\n  "server_port": 22\n}'
                    }
                    required={!initial}
                    value={spec.outbound_json ?? ""}
                  />
                  <p className="text-xs text-muted-foreground">
                    {t("transports.form.outboundJsonHint")}
                  </p>
                </Field>
              )}
              <Field label={t("transports.form.mtu")}>
                <Input
                  min={576}
                  max={9000}
                  onChange={(event) =>
                    setSpec({ ...spec, mtu: Number(event.target.value) })
                  }
                  type="number"
                  value={spec.mtu ?? 1420}
                />
              </Field>
              <Field label={t("transports.form.tunAddress")}>
                <Input
                  onChange={(event) =>
                    setSpec({
                      ...spec,
                      tun_address: event.target.value.trim() || undefined,
                    })
                  }
                  pattern="(?:[0-9]{1,3}\\.){3}[0-9]{1,3}/30"
                  placeholder={t("transports.form.tunAddressPlaceholder")}
                  title={t("transports.form.tunAddressHint")}
                  value={spec.tun_address ?? ""}
                />
                <p className="text-xs text-muted-foreground">
                  {t("transports.form.tunAddressHint")}
                </p>
              </Field>
              <Field label={t("transports.form.bootstrapDns")}>
                <Textarea
                  className="min-h-20 font-mono text-xs"
                  onChange={(event) =>
                    setSpec({
                      ...spec,
                      bootstrap_dns: event.target.value
                        .split(/[\n,]/)
                        .map((value) => value.trim())
                        .filter(Boolean),
                    })
                  }
                  placeholder={"1.1.1.1\n9.9.9.9"}
                  value={(spec.bootstrap_dns ?? []).join("\n")}
                />
                <p className="text-xs text-muted-foreground">
                  {t("transports.form.bootstrapDnsHint")}
                </p>
              </Field>
            </div>
          ) : null}

          <DialogFooter>
            <Button
              disabled={isPending}
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
            >
              {t("common.cancel")}
            </Button>
            <Button disabled={isPending} type="submit">
              {isPending
                ? t("transports.form.saving")
                : t("transports.form.save")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function Field({ children, label }: { children: ReactNode; label: string }) {
  return (
    <div className="grid gap-1.5">
      <Label>{label}</Label>
      {children}
    </div>
  )
}

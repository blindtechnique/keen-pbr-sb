import { ServerCog } from "lucide-react"

import type { PlainDnsTemplate } from "@/api/generated/model/plainDnsTemplate"
import {
  getSavedDnsTemplateSelection,
  type DnsPresetSelection,
} from "@/components/dns/dns-preset-selection"
import cloudflareLogoUrl from "../../../../logos/Cloudflare.svg"
import googleLogoUrl from "../../../../logos/google.svg"
import openDnsLogoUrl from "../../../../logos/opendns.svg"
import quad9LogoUrl from "../../../../logos/quad9.svg"
import yandexLogoUrl from "../../../../logos/yandex.svg"

import { DNS_PRESETS, type DnsPresetId } from "@/data/dns-presets"
import { cn } from "@/lib/utils"

const LOGO_BY_PRESET: Readonly<Record<DnsPresetId, string>> = {
  yandex: yandexLogoUrl,
  google: googleLogoUrl,
  cloudflare: cloudflareLogoUrl,
  quad9: quad9LogoUrl,
  opendns: openDnsLogoUrl,
}

export function DnsPresetPicker({
  customLabel,
  label,
  onValueChange,
  savedTemplates = [],
  showCustom = true,
  value,
}: {
  customLabel: string
  label: string
  onValueChange: (value: DnsPresetSelection) => void
  savedTemplates?: PlainDnsTemplate[]
  showCustom?: boolean
  value: DnsPresetSelection
}) {
  return (
    <fieldset className="space-y-2.5">
      <legend className="text-sm font-medium text-foreground">{label}</legend>
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
        {DNS_PRESETS.map((preset) => (
          <PresetButton
            active={value === preset.id}
            key={preset.id}
            label={preset.name}
            logoUrl={LOGO_BY_PRESET[preset.id]}
            onClick={() => onValueChange(preset.id)}
          />
        ))}
        {savedTemplates.map((template) => {
          const selection = getSavedDnsTemplateSelection(template)
          return (
            <button
              aria-pressed={value === selection}
              className={cn(
                "flex min-h-16 min-w-0 items-center gap-3 rounded-[4px] border bg-background px-3 py-2 text-left transition-[border-color,background-color,box-shadow] hover:border-primary/60 hover:shadow-sm",
                value === selection &&
                  "border-primary bg-primary/8 shadow-[inset_0_0_0_1px_var(--color-primary)]"
              )}
              key={selection}
              onClick={() => onValueChange(selection)}
              type="button"
            >
              <span className="flex size-9 shrink-0 items-center justify-center rounded-full bg-muted text-primary">
                <ServerCog className="size-5" />
              </span>
              <span className="min-w-0">
                <span className="block truncate text-sm font-medium">
                  {template.name}
                </span>
                <span className="block truncate text-xs text-muted-foreground">
                  {template.primary_ipv4}
                  {template.secondary_ipv4
                    ? ` / ${template.secondary_ipv4}`
                    : ""}
                </span>
              </span>
            </button>
          )
        })}
        {showCustom ? (
          <button
            aria-pressed={value === "custom"}
            className={cn(
              "flex min-h-16 items-center gap-3 rounded-[4px] border bg-background px-3 py-2 text-left transition-[border-color,background-color,box-shadow] hover:border-primary/60 hover:shadow-sm",
              value === "custom" &&
                "border-primary bg-primary/8 shadow-[inset_0_0_0_1px_var(--color-primary)]"
            )}
            onClick={() => onValueChange("custom")}
            type="button"
          >
            <span className="flex size-9 shrink-0 items-center justify-center rounded-full bg-muted text-primary">
              <ServerCog className="size-5" />
            </span>
            <span className="min-w-0 text-sm font-medium">{customLabel}</span>
          </button>
        ) : null}
      </div>
    </fieldset>
  )
}

function PresetButton({
  active,
  label,
  logoUrl,
  onClick,
}: {
  active: boolean
  label: string
  logoUrl: string
  onClick: () => void
}) {
  return (
    <button
      aria-pressed={active}
      className={cn(
        "flex min-h-16 items-center justify-center rounded-[4px] border bg-background px-3 py-2 transition-[border-color,background-color,box-shadow] hover:border-primary/60 hover:shadow-sm",
        active &&
          "border-primary bg-primary/8 shadow-[inset_0_0_0_1px_var(--color-primary)]"
      )}
      onClick={onClick}
      title={label}
      type="button"
    >
      <img
        alt={label}
        className="h-8 max-w-full object-contain dark:brightness-110"
        src={logoUrl}
      />
    </button>
  )
}

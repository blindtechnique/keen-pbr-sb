import type { InternalVpnServerInventoryState } from "@/components/settings/internal-vpn-servers-field"
import type { NdmsVpnServerService } from "@/api/generated/model/ndmsVpnServerService"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"
import {
  buildInternalVpnServiceOptions,
  getInternalVpnServiceProcessClients,
  hasInternalVpnServiceOverride,
  removeInternalVpnServiceOverride,
  type InternalVpnServicePolicyOverride,
  updateInternalVpnServiceOverride,
} from "@/lib/internal-vpn-service-policy"

export interface InternalVpnServicesFieldCopy {
  readonly title: string
  readonly description: string
  readonly emptyTitle: string
  readonly emptyDescription: string
  readonly loadingTitle: string
  readonly loadingDescription: string
  readonly unavailableTitle: string
  readonly unavailableDescription: string
  readonly staleTitle: string
  readonly staleDescription: string
  readonly loadErrorTitle: string
  readonly loadErrorDescription: string
  readonly processLabel: string
  readonly inheritLabel: string
  /** Имя службы по её виду: подпись обязана меняться вместе с языком панели. */
  readonly serviceName: (kind: NdmsVpnServerService["kind"]) => string
  readonly statusEnabled: string
  readonly statusDisabled: string
  readonly statusMissing: string
  readonly poolLabel: string
  readonly boundInterfaceLabel: string
  readonly unavailableHint: string
  readonly toggleAriaLabel: (serviceLabel: string) => string
  readonly inheritAriaLabel: (serviceLabel: string) => string
}

interface InternalVpnServicesFieldProps {
  readonly services: readonly NdmsVpnServerService[]
  readonly overrides?: readonly InternalVpnServicePolicyOverride[]
  readonly baselineOverrides?: readonly InternalVpnServicePolicyOverride[]
  readonly legacyInboundInterfaces?: readonly string[]
  readonly onChange: (
    overrides: InternalVpnServicePolicyOverride[] | undefined
  ) => void
  readonly copy: InternalVpnServicesFieldCopy
  readonly disabled?: boolean
  readonly inventoryState?: InternalVpnServerInventoryState
}

export function InternalVpnServicesField({
  services,
  overrides,
  baselineOverrides,
  legacyInboundInterfaces,
  onChange,
  copy,
  disabled = false,
  inventoryState = "ready",
}: InternalVpnServicesFieldProps) {
  const options = buildInternalVpnServiceOptions({ services, overrides })
  const inventoryNotice =
    inventoryState === "loading"
      ? {
          title: copy.loadingTitle,
          description: copy.loadingDescription,
          role: "status" as const,
        }
      : inventoryState === "unavailable"
        ? {
            title: copy.unavailableTitle,
            description: copy.unavailableDescription,
            role: "status" as const,
          }
        : inventoryState === "stale"
          ? {
              title: copy.staleTitle,
              description: copy.staleDescription,
              role: "status" as const,
            }
          : inventoryState === "error"
            ? {
                title: copy.loadErrorTitle,
                description: copy.loadErrorDescription,
                role: "alert" as const,
              }
            : null

  return (
    <section aria-labelledby="internal-vpn-services-title">
      <div className="mb-3">
        <h3
          className="text-base font-semibold text-foreground"
          id="internal-vpn-services-title"
        >
          {copy.title}
        </h3>
        <p className="mt-1 text-sm text-muted-foreground">{copy.description}</p>
      </div>

      {inventoryNotice ? (
        <div
          aria-live="polite"
          className="border-y border-border py-4"
          role={inventoryNotice.role}
        >
          <p className="text-sm font-medium text-foreground">
            {inventoryNotice.title}
          </p>
          <p className="mt-1 text-sm text-muted-foreground">
            {inventoryNotice.description}
          </p>
        </div>
      ) : null}

      {options.length === 0 ? (
        !inventoryNotice ? (
          <div className="border-y border-border py-4">
            <p className="text-sm font-medium text-foreground">
              {copy.emptyTitle}
            </p>
            <p className="mt-1 text-sm text-muted-foreground">
              {copy.emptyDescription}
            </p>
          </div>
        ) : null
      ) : (
        <div className="divide-y divide-border border-y border-border">
          {options.map((service) => {
            const checked = getInternalVpnServiceProcessClients({
              serviceId: service.serviceId,
              overrides,
              legacyInboundInterfaces,
            })
            const hasExplicitOverride = hasInternalVpnServiceOverride(
              service.serviceId,
              overrides
            )
            const isAuthoritative =
              inventoryState === "ready" &&
              !service.missing &&
              service.enabled &&
              service.sourceCidrs.length > 0

            return (
              <div
                className="flex min-w-0 items-center gap-4 py-3"
                key={service.key}
              >
                <div className="min-w-0 flex-1">
                  <div className="flex min-w-0 flex-wrap items-center gap-2">
                    {/* Имя вместо внутреннего идентификатора прошивки:
                        `VPNL2TPServer` и `VirtualIPServerIKE2` не говорят ни
                        что это VPN-сервер, ни какой именно. Пилюля с типом
                        протокола после этого не нужна — он уже в названии.
                        Исходное имя осталось в подсказке. */}
                    <span
                      className="truncate text-sm font-medium text-foreground"
                      title={service.label}
                    >
                      {service.kind ? copy.serviceName(service.kind) : service.label}
                    </span>
                    <Badge
                      size="xs"
                      variant={
                        service.enabled && !service.missing
                          ? "success"
                          : "outline"
                      }
                    >
                      {service.missing
                        ? copy.statusMissing
                        : service.enabled
                          ? copy.statusEnabled
                          : copy.statusDisabled}
                    </Badge>
                  </div>

                  {service.sourceCidrs.length > 0 ? (
                    <p className="mt-1 break-words text-xs text-muted-foreground">
                      {copy.poolLabel}: {service.sourceCidrs.join(", ")}
                    </p>
                  ) : null}
                  {service.boundInterfaceId ? (
                    <p className="mt-1 text-xs text-muted-foreground">
                      {copy.boundInterfaceLabel}: {service.boundInterfaceId}
                    </p>
                  ) : null}
                  {!isAuthoritative ? (
                    <p className="mt-1 text-xs text-muted-foreground">
                      {copy.unavailableHint}
                    </p>
                  ) : null}
                </div>

                <div className="flex shrink-0 items-center gap-2">
                  {hasExplicitOverride ? (
                    <Button
                      aria-label={copy.inheritAriaLabel(service.label)}
                      className="h-auto px-1.5 py-1 text-xs"
                      disabled={disabled}
                      onClick={() =>
                        onChange(
                          removeInternalVpnServiceOverride({
                            serviceId: service.serviceId,
                            overrides,
                            baselineOverrides,
                          })
                        )
                      }
                      size="xs"
                      type="button"
                      variant="link"
                    >
                      {copy.inheritLabel}
                    </Button>
                  ) : null}
                  <label className="flex items-center gap-3 text-sm text-foreground">
                    <span className="hidden sm:inline">{copy.processLabel}</span>
                    <Switch
                      aria-label={copy.toggleAriaLabel(service.label)}
                      checked={checked}
                      disabled={disabled || !isAuthoritative}
                      onCheckedChange={(processClients) =>
                        onChange(
                          updateInternalVpnServiceOverride({
                            serviceId: service.serviceId,
                            processClients,
                            overrides,
                            baselineOverrides,
                            legacyInboundInterfaces,
                          })
                        )
                      }
                    />
                  </label>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </section>
  )
}

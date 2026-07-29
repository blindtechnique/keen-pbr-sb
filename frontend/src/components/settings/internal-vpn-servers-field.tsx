import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"
import {
  buildInternalVpnServerOptions,
  getInternalVpnServerProcessClients,
  getInternalVpnServerStatus,
  hasInternalVpnServerOverride,
  removeInternalVpnServerOverride,
  type InternalVpnServerRuntimeState,
  type InternalVpnServerPolicyOverride,
  updateInternalVpnServerOverride,
} from "@/lib/internal-vpn-server-policy"
import type { NativeInterfaceModel } from "@/lib/native-interfaces"

export type InternalVpnServerInventoryState =
  | "loading"
  | "ready"
  | "stale"
  | "unavailable"
  | "error"

export interface InternalVpnServersFieldCopy {
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
  readonly confirmationTitle: string
  readonly confirmationDescription: string
  readonly confirmationAction: string
  readonly processLabel: string
  readonly inheritLabel: string
  readonly statusUp: string
  readonly statusDown: string
  readonly statusMissing: string
  readonly statusUnknown: string
  readonly missingHint: string
  readonly confirmationAriaLabel: (serverLabel: string) => string
  readonly toggleAriaLabel: (serverLabel: string) => string
  readonly inheritAriaLabel: (serverLabel: string) => string
}

interface InternalVpnServersFieldProps {
  readonly nativeInterfaces: readonly NativeInterfaceModel[]
  readonly overrides?: readonly InternalVpnServerPolicyOverride[]
  readonly baselineOverrides?: readonly InternalVpnServerPolicyOverride[]
  readonly legacyInboundInterfaces?: readonly string[]
  readonly onChange: (
    overrides: InternalVpnServerPolicyOverride[] | undefined
  ) => void
  readonly onRolelessConfirmationChange?: (
    ndmsId: string,
    confirmed: boolean
  ) => void
  readonly copy: InternalVpnServersFieldCopy
  readonly disabled?: boolean
  readonly inventoryState?: InternalVpnServerInventoryState
  readonly runtimeState?: InternalVpnServerRuntimeState
}

/**
 * Controlled field for the settings form. It owns no draft and performs no
 * request, so edits participate in the page's existing Save/Cancel transaction
 * instead of being applied when the switch is clicked.
 */
export function InternalVpnServersField({
  nativeInterfaces,
  overrides,
  baselineOverrides,
  legacyInboundInterfaces,
  onChange,
  onRolelessConfirmationChange,
  copy,
  disabled = false,
  inventoryState = "ready",
  runtimeState = "ready",
}: InternalVpnServersFieldProps) {
  const servers = buildInternalVpnServerOptions({
    nativeInterfaces,
    overrides,
  })
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
    <section aria-labelledby="internal-vpn-servers-title">
      <div className="mb-3">
        <h3
          className="text-base font-semibold text-foreground"
          id="internal-vpn-servers-title"
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

      {servers.length === 0 ? (
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
          {servers.map((server) => {
            const checked = getInternalVpnServerProcessClients({
              ndmsId: server.ndmsId,
              interfaceName: server.interfaceName,
              overrides,
              legacyInboundInterfaces,
            })
            const hasExplicitOverride = hasInternalVpnServerOverride(
              server.interfaceName,
              overrides,
              server.ndmsId
            )
            const confirmationPending =
              server.requiresRoleConfirmation && !hasExplicitOverride
            const status = getInternalVpnServerStatus({
              server,
              inventoryReady: inventoryState === "ready",
              runtimeState,
            })

            return (
              <div
                className="flex min-w-0 items-center gap-4 py-3"
                key={server.key}
              >
                <div className="min-w-0 flex-1">
                  <div className="flex min-w-0 flex-wrap items-center gap-2">
                    <span className="truncate text-sm font-medium text-foreground">
                      {server.label}
                    </span>
                    {server.protocol ? (
                      <Badge size="xs" variant="outline">
                        {server.protocol}
                      </Badge>
                    ) : null}
                    <Badge
                      size="xs"
                      variant={status === "up" ? "success" : "outline"}
                    >
                      {status === "up"
                        ? copy.statusUp
                        : status === "down"
                          ? copy.statusDown
                          : status === "missing"
                            ? copy.statusMissing
                            : copy.statusUnknown}
                    </Badge>
                  </div>

                  <div className="mt-1 flex min-w-0 flex-wrap gap-x-2 text-xs text-muted-foreground">
                    {server.logicalName ? (
                      <span className="truncate">{server.logicalName}</span>
                    ) : null}
                    <code className="truncate font-mono">
                      {server.interfaceName}
                    </code>
                  </div>

                  {server.missing ? (
                    <p className="mt-1 text-xs text-muted-foreground">
                      {copy.missingHint}
                    </p>
                  ) : null}
                  {confirmationPending ? (
                    <div className="mt-2 border-l-2 border-warning pl-3">
                      <p className="text-xs font-medium text-foreground">
                        {copy.confirmationTitle}
                      </p>
                      <p className="mt-0.5 text-xs text-muted-foreground">
                        {copy.confirmationDescription}
                      </p>
                    </div>
                  ) : null}
                </div>

                <div className="flex shrink-0 items-center gap-2">
                  {hasExplicitOverride ? (
                    <Button
                      aria-label={copy.inheritAriaLabel(server.label)}
                      className="h-auto px-1.5 py-1 text-xs"
                      disabled={disabled}
                      onClick={() => {
                        if (server.ndmsId) {
                          onRolelessConfirmationChange?.(
                            server.ndmsId,
                            false
                          )
                        }
                        onChange(
                          removeInternalVpnServerOverride({
                            ndmsId: server.ndmsId,
                            interfaceName: server.interfaceName,
                            overrides,
                            baselineOverrides,
                          })
                        )
                      }}
                      size="xs"
                      type="button"
                      variant="link"
                    >
                      {copy.inheritLabel}
                    </Button>
                  ) : null}
                  {confirmationPending ? (
                    <Button
                      aria-label={copy.confirmationAriaLabel(server.label)}
                      disabled={disabled || inventoryState !== "ready"}
                      onClick={() => {
                        if (server.ndmsId) {
                          onRolelessConfirmationChange?.(
                            server.ndmsId,
                            true
                          )
                        }
                        onChange(
                          updateInternalVpnServerOverride({
                            ndmsId: server.ndmsId,
                            interfaceName: server.interfaceName,
                            processClients: checked,
                            forceExplicit: true,
                            overrides,
                            baselineOverrides,
                            legacyInboundInterfaces,
                          })
                        )
                      }}
                      size="sm"
                      type="button"
                      variant="outline"
                    >
                      {copy.confirmationAction}
                    </Button>
                  ) : (
                    <label className="flex items-center gap-3 text-sm text-foreground">
                      <span className="hidden sm:inline">
                        {copy.processLabel}
                      </span>
                      <Switch
                        aria-label={copy.toggleAriaLabel(server.label)}
                        checked={checked}
                        disabled={
                          disabled ||
                          server.missing ||
                          inventoryState !== "ready"
                        }
                        onCheckedChange={(processClients) =>
                          onChange(
                            updateInternalVpnServerOverride({
                              ndmsId: server.ndmsId,
                              interfaceName: server.interfaceName,
                              processClients,
                              forceExplicit:
                                server.requiresRoleConfirmation,
                              overrides,
                              baselineOverrides,
                              legacyInboundInterfaces,
                            })
                          )
                        }
                      />
                    </label>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      )}
    </section>
  )
}

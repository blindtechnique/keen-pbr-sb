import { useTranslation } from "react-i18next"

import type {
  Outbound,
  RuntimeInterfaceState,
  RuntimeOutboundState,
  TransportSpec,
} from "@/api/generated/model"
import { useGetTransportConfig } from "@/api/generated/keen-api"
import { InterfaceLabel } from "@/components/shared/interface-label"
import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"

/**
 * One glanceable row per outbound: what carries the traffic (protocol), whether
 * it is a single link or a failover group, and whether it is alive right now.
 */
export function OutboundStateList({
  outbounds,
  runtimeByTag,
}: {
  outbounds: Outbound[]
  runtimeByTag: Map<string, RuntimeOutboundState>
}) {
  const { t } = useTranslation()
  const protocolByInterface = useProtocolByInterface()

  return (
    <div className="divide-y">
      {outbounds.map((outbound) => {
        const runtime = runtimeByTag.get(outbound.tag)
        const children = runtime?.interfaces ?? []
        const isGroup = outbound.type === "urltest"

        return (
          <div className="py-2.5 first:pt-0 last:pb-0" key={outbound.tag}>
            <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
              <HealthDot status={runtime?.status} />
              <span className="font-medium">{outbound.tag}</span>
              <Badge size="xs" variant="outline">
                {describeKind(outbound, protocolByInterface, t)}
              </Badge>
              {outbound.type === "interface" && outbound.interface ? (
                <InterfaceLabel name={outbound.interface} />
              ) : null}
              {isGroup ? (
                <span className="text-xs text-muted-foreground">
                  {t("overview.outbounds.members", { count: children.length })}
                </span>
              ) : null}
              <span className="ml-auto">
                <StatusBadge status={runtime?.status} t={t} />
              </span>
            </div>

            {isGroup && children.length > 0 ? (
              <div className="mt-1.5 space-y-1 pl-4">
                {children.map((child) => (
                  <MemberRow
                    child={child}
                    key={`${outbound.tag}-${child.outbound_tag}`}
                    protocolByInterface={protocolByInterface}
                    t={t}
                  />
                ))}
              </div>
            ) : null}

            {runtime?.detail ? (
              <p className="mt-1 pl-4 text-xs text-muted-foreground">
                {runtime.detail}
              </p>
            ) : null}
          </div>
        )
      })}
    </div>
  )
}

function MemberRow({
  child,
  protocolByInterface,
  t,
}: {
  child: RuntimeInterfaceState
  protocolByInterface: Map<string, string>
  t: (key: string, options?: Record<string, unknown>) => string
}) {
  const protocol = child.interface_name
    ? protocolByInterface.get(child.interface_name)
    : undefined
  const isActive = child.status === "active"

  return (
    <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5 text-sm">
      <span
        className={cn(
          "size-1.5 rounded-full",
          isActive
            ? "bg-success"
            : child.status === "backup"
              ? "bg-muted-foreground/50"
              : "bg-destructive"
        )}
      />
      <span className={cn(isActive && "font-medium")}>
        {child.outbound_tag}
      </span>
      {protocol ? (
        <span className="text-xs text-muted-foreground uppercase">
          {protocol}
        </span>
      ) : null}
      {child.interface_name ? (
        <InterfaceLabel name={child.interface_name} />
      ) : null}
      <span className="ml-auto flex items-center gap-2">
        {typeof child.latency_ms === "number" ? (
          <span className="text-xs tabular-nums text-muted-foreground">
            {child.latency_ms} ms
          </span>
        ) : null}
        <Badge size="xs" variant={isActive ? "success" : "secondary"}>
          {t(`overview.outbounds.member.${child.status}`)}
        </Badge>
      </span>
    </div>
  )
}

function HealthDot({ status }: { status?: string }) {
  return (
    <span
      className={cn(
        "size-2 shrink-0 rounded-full",
        status === "healthy"
          ? "bg-success"
          : status === "degraded"
            ? "bg-destructive"
            : "bg-warning"
      )}
    />
  )
}

function StatusBadge({
  status,
  t,
}: {
  status?: string
  t: (key: string, options?: Record<string, unknown>) => string
}) {
  if (!status) {
    return null
  }

  return (
    <Badge
      size="xs"
      variant={
        status === "healthy"
          ? "success"
          : status === "degraded"
            ? "destructive"
            : "warning"
      }
    >
      {/* Falling back to the raw value keeps a status the daemon grew but the
          translations have not from being printed as a key path. */}
      {t(`overview.outbounds.status.${status}`, { defaultValue: status })}
    </Badge>
  )
}

/** Reads the protocol out of the transport share links, keyed by interface. */
function useProtocolByInterface() {
  const transportConfigQuery = useGetTransportConfig()
  const transports: TransportSpec[] =
    transportConfigQuery.data?.status === 200
      ? transportConfigQuery.data.data
      : []

  const map = new Map<string, string>()
  for (const transport of transports) {
    if (!transport.interface) continue
    map.set(transport.interface, describeTransportProtocol(transport))
  }
  return map
}

function describeTransportProtocol(transport: {
  type?: string
  link?: string
  outbound_json?: string
}): string {
  if (transport.type === "native") {
    return "wireguard"
  }
  const scheme = transport.link?.match(/^([a-z0-9]+):\/\//i)?.[1]
  if (scheme) {
    return scheme.toLowerCase()
  }
  const jsonType = transport.outbound_json?.match(/"type"\s*:\s*"([a-z0-9-]+)"/i)
  return jsonType?.[1]?.toLowerCase() ?? "sing-box"
}

function describeKind(
  outbound: Outbound,
  protocolByInterface: Map<string, string>,
  t: (key: string) => string
): string {
  switch (outbound.type) {
    case "urltest":
      return t("overview.outbounds.kind.failover")
    case "table":
      return t("overview.outbounds.kind.table")
    case "blackhole":
      return t("overview.outbounds.kind.blackhole")
    case "ignore":
      return t("overview.outbounds.kind.ignore")
    default: {
      const protocol = outbound.interface
        ? protocolByInterface.get(outbound.interface)
        : undefined
      return protocol ? protocol.toUpperCase() : t("overview.outbounds.kind.interface")
    }
  }
}

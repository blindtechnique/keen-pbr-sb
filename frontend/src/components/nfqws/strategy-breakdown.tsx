import { useMemo } from "react"
import { useTranslation } from "react-i18next"

import { Badge } from "@/components/ui/badge"
import {
  nfqwsProtocolLabel,
  parseNfqwsStrategy,
  type NfqwsPool,
} from "@/pages/nfqws-strategy-model"

/** Read-only explanation of the exact strategy text shown in the raw editor. */
export function StrategyBreakdown({ content }: { content: string }) {
  const { t } = useTranslation()
  const summary = useMemo(() => parseNfqwsStrategy(content), [content])

  if (!summary.parseable) {
    return (
      <p className="text-sm text-muted-foreground" role="status">
        {t("nfqws.breakdown.unparseable")}
      </p>
    )
  }

  return (
    <div className="space-y-3">
      {summary.status === "partial" ? (
        <p
          className="rounded-lg border border-warning/40 bg-warning/5 px-3 py-2 text-sm text-warning-foreground"
          role="status"
        >
          {t("nfqws.breakdown.partial")}
        </p>
      ) : null}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
        <span>
          {t("nfqws.breakdown.poolCount", { count: summary.pools.length })}
        </span>
        {summary.blobCount > 0 ? (
          <span>
            {t("nfqws.breakdown.blobCount", { count: summary.blobCount })}
          </span>
        ) : null}
      </div>
      <ul className="grid gap-2 lg:grid-cols-2">
        {summary.pools.map((pool) => (
          <PoolCard key={pool.id} pool={pool} />
        ))}
      </ul>
    </div>
  )
}

function PoolCard({ pool }: { pool: NfqwsPool }) {
  const { t } = useTranslation()
  const title = poolTitle(pool, t)
  const transportLabel =
    pool.transport === "tcp"
      ? "TCP"
      : pool.transport === "udp"
        ? "UDP"
        : t("nfqws.breakdown.unknownTransport")

  return (
    <li className="min-w-0 space-y-2 rounded-xl border p-3">
      <div className="flex min-w-0 flex-wrap items-center gap-2">
        <span className="min-w-0 truncate text-sm font-medium" title={title}>
          {title}
        </span>
        <Badge size="xs" variant={pool.filterOnly ? "success" : "secondary"}>
          {pool.filterOnly ? t("nfqws.breakdown.passthrough") : transportLabel}
        </Badge>
        {pool.protocols.map((protocol) => (
          <Badge key={protocol} size="xs" variant="outline">
            {nfqwsProtocolLabel(protocol)}
          </Badge>
        ))}
      </div>

      {pool.tcpPorts ? (
        <p className="text-xs text-muted-foreground">
          {t("nfqws.breakdown.tcpPorts", { ports: pool.tcpPorts })}
        </p>
      ) : null}
      {pool.udpPorts ? (
        <p className="text-xs text-muted-foreground">
          {t("nfqws.breakdown.udpPorts", { ports: pool.udpPorts })}
        </p>
      ) : null}

      {pool.domains.length > 0 ? (
        <p
          className="truncate text-xs text-muted-foreground"
          title={pool.domains.join(", ")}
        >
          {t("nfqws.breakdown.domains")}: {pool.domains.slice(0, 3).join(", ")}
          {pool.domains.length > 3
            ? ` ${t("nfqws.breakdown.domainsMore", {
                count: pool.domains.length - 3,
              })}`
            : ""}
        </p>
      ) : null}

      {pool.filterOnly ? (
        <p className="text-xs text-muted-foreground">
          {t("nfqws.breakdown.passthroughDescription")}
        </p>
      ) : pool.rotation ? (
        <div className="space-y-1 text-xs text-muted-foreground">
          <p className="font-medium text-foreground">
            {t("nfqws.breakdown.rotation", { count: pool.rotation.slots })}
          </p>
          {pool.rotation.fails !== undefined ||
          pool.rotation.inseq !== undefined ? (
            <p>
              {pool.rotation.fails !== undefined
                ? t("nfqws.breakdown.switchAfter", {
                    count: pool.rotation.fails,
                  })
                : null}
              {pool.rotation.inseq !== undefined
                ? ` · ${t("nfqws.breakdown.inseq", {
                    value: pool.rotation.inseq,
                  })}`
                : null}
            </p>
          ) : null}
        </div>
      ) : (
        <p className="text-xs text-muted-foreground">
          {t("nfqws.breakdown.noRotation")}
        </p>
      )}

      {pool.techniques.length > 0 ? (
        <div className="flex flex-wrap gap-1">
          {pool.techniques.map((technique) => (
            <Badge key={technique} size="xs" variant="outline">
              {technique}
            </Badge>
          ))}
        </div>
      ) : null}
    </li>
  )
}

function poolTitle(pool: NfqwsPool, t: (key: string) => string): string {
  if (pool.domains.length > 0) {
    const first = pool.domains[0] ?? ""
    return pool.domains.length > 1
      ? `${first} +${pool.domains.length - 1}`
      : first
  }
  if (pool.name && !pool.name.endsWith("_general")) return pool.name
  if (pool.varName === "NFQWS_ARGS") return t("nfqws.breakdown.pools.main")
  if (pool.varName === "NFQWS_ARGS_QUIC") {
    return t("nfqws.breakdown.pools.quic")
  }
  if (pool.varName === "NFQWS_ARGS_UDP") {
    return t("nfqws.breakdown.pools.udp")
  }
  return pool.name ?? pool.varName
}

import { useEffect, useRef, useState } from "react"
import { useTranslation } from "react-i18next"
import type { ConfigObject } from "@/api/generated/model"
import { Button } from "@/components/ui/button"
import { Textarea } from "@/components/ui/textarea"
import { Checkbox } from "@/components/ui/checkbox"
import { Label } from "@/components/ui/label"
import { downloadJson, formatDownloadTimestamp } from "@/lib/download"
import { createOutboundDisplayNameMap } from "@/lib/outbound-display"
import { httpProbeReason } from "./routing-http-probe-copy"
import {
  batchOutcome,
  batchReport,
  makeBatchPlan,
  runRoutingBatch,
  type BatchPath,
  type BatchRow,
} from "./routing-batch-model"

export function RoutingBatchPanel({
  outbounds,
  busy = false,
  onRunning,
}: {
  outbounds?: ConfigObject["outbounds"]
  busy?: boolean
  onRunning: (running: boolean) => void
}) {
  const { t } = useTranslation()
  const [text, setText] = useState("")
  const [paths, setPaths] = useState<string[]>(["policy"])
  const [families, setFamilies] = useState<("ipv4" | "ipv6")[]>(["ipv4"])
  const [rows, setRows] = useState<BatchRow[]>([])
  const [running, setRunning] = useState(false)
  const [stopping, setStopping] = useState(false)
  const [error, setError] = useState<"targets" | "selection" | "limit" | null>(
    null
  )
  const controller = useRef<AbortController | null>(null)
  const mounted = useRef(true)
  useEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
      controller.current?.abort()
    }
  }, [])
  const labels = createOutboundDisplayNameMap(outbounds ?? [])
  const choices: (BatchPath & { id: string })[] = [
    { id: "policy", path: "policy", label: t("overview.batch.policy") },
    { id: "direct", path: "direct", label: t("overview.batch.direct") },
    ...(outbounds ?? [])
      .filter((outbound) => outbound.type === "interface")
      .map((outbound) => ({
        id: `outbound:${outbound.tag}`,
        path: "outbound" as const,
        outbound: outbound.tag,
        label: labels.get(outbound.tag) ?? outbound.tag,
      })),
  ]
  const plan = makeBatchPlan(
    text,
    choices.filter((choice) => paths.includes(choice.id)),
    families
  )
  const togglePath = (value: string, checked: boolean) =>
    setPaths((before) =>
      checked ? [...before, value] : before.filter((item) => item !== value)
    )
  return (
    <details className="space-y-3 rounded-md border p-3">
      <summary className="cursor-pointer font-medium">
        {t("overview.batch.title")}
        {running ? (
          <span className="ml-2 text-sm font-normal">
            {stopping
              ? t("overview.batch.stopping")
              : t("overview.batch.progress", {
                  count: rows.filter(
                    (row) => row.state === "done" || row.state === "failed"
                  ).length,
                  total: rows.length,
                })}
          </span>
        ) : null}
      </summary>
      <p className="text-sm text-muted-foreground">
        {t("overview.batch.description")}
      </p>
      <p className="text-sm text-muted-foreground">
        {t("overview.batch.influence")}
      </p>
      <form
        className="space-y-3"
        onSubmit={async (event) => {
          event.preventDefault()
          if (controller.current || busy) return
          if (plan.error) {
            setError(plan.error)
            return
          }
          setError(null)
          const active = new AbortController()
          controller.current = active
          setRunning(true)
          setStopping(false)
          onRunning(true)
          try {
            await runRoutingBatch(plan.items, active.signal, (next) => {
              if (mounted.current) setRows(next)
            })
          } finally {
            controller.current = null
            if (mounted.current) {
              setRunning(false)
              setStopping(false)
              onRunning(false)
            }
          }
        }}
      >
        <Label htmlFor="batch-targets">{t("overview.batch.targets")}</Label>
        <Textarea
          id="batch-targets"
          value={text}
          disabled={running}
          maxLength={24588}
          placeholder={t("overview.batch.placeholder")}
          onChange={(event) => setText(event.target.value)}
        />
        <fieldset disabled={running} className="space-y-2">
          <legend className="mb-2 text-sm font-medium">
            {t("overview.batch.paths")}
          </legend>
          <div className="flex flex-wrap gap-x-5 gap-y-2">
            {choices.map((choice) => (
              <Label key={choice.id} className="font-normal">
                <Checkbox
                  checked={paths.includes(choice.id)}
                  disabled={running}
                  onCheckedChange={(checked) =>
                    togglePath(choice.id, checked === true)
                  }
                />
                {choice.label}
              </Label>
            ))}
          </div>
          <p className="text-xs text-muted-foreground">
            {t("overview.batch.pathHelp")}
          </p>
        </fieldset>
        <fieldset disabled={running} className="flex gap-5">
          <legend className="mb-2 text-sm font-medium">
            {t("overview.batch.family")}
          </legend>
          {(["ipv4", "ipv6"] as const).map((family) => (
            <Label key={family}>
              <Checkbox
                checked={families.includes(family)}
                disabled={running}
                onCheckedChange={(checked) =>
                  setFamilies((before) =>
                    checked
                      ? [...before, family]
                      : before.filter((item) => item !== family)
                  )
                }
              />
              {family === "ipv4" ? "IPv4" : "IPv6"}
            </Label>
          ))}
        </fieldset>
        {error ? (
          <p role="alert" className="text-sm text-destructive">
            {error === "targets"
              ? t("overview.batch.invalidTargets")
              : error === "selection"
                ? t("overview.batch.selectPaths")
                : t("overview.batch.limit")}
          </p>
        ) : null}
        <div className="flex flex-wrap items-center gap-3">
          <Button type="submit" disabled={running || busy}>
            {t("overview.batch.start")}
          </Button>
          {running ? (
            <Button
              type="button"
              variant="outline"
              disabled={stopping}
              onClick={() => {
                controller.current?.abort()
                setStopping(true)
              }}
            >
              {t("overview.batch.stop")}
            </Button>
          ) : null}
          <span
            role="status"
            aria-live="polite"
            className="text-sm text-muted-foreground"
          >
            {stopping
              ? t("overview.batch.stopping")
              : running
                ? t("overview.batch.progress", {
                    count: rows.filter(
                      (row) => row.state === "done" || row.state === "failed"
                    ).length,
                    total: rows.length,
                  })
                : t("overview.batch.count", { count: plan.items.length })}
          </span>
        </div>
      </form>
      <RoutingBatchResults rows={rows} />
      {rows.length > 0 && !running ? (
        <div className="space-y-2">
          <Button
            variant="outline"
            onClick={() =>
              downloadJson(
                `site-comparison-${formatDownloadTimestamp()}.json`,
                batchReport(rows)
              )
            }
          >
            {t("overview.batch.export")}
          </Button>
          <p className="text-xs text-muted-foreground">
            {t("overview.batch.exportPrivacy")}
          </p>
        </div>
      ) : null}
    </details>
  )
}

export function RoutingBatchResults({ rows }: { rows: readonly BatchRow[] }) {
  const { t } = useTranslation()
  if (!rows.length) return null
  return (
    <div className="space-y-3" aria-live="polite">
      {rows.map((row, index) => {
        const http = row.response?.http_probe
        const outcome = batchOutcome(row)
        const dnsSource = !row.response
          ? "—"
          : !row.response.is_domain
            ? t("overview.routingDiagnostics.evidence.dnsLiteral")
            : row.response.dns_source === "configured_resolver"
              ? t("overview.routingDiagnostics.evidence.dnsConfigured")
              : row.response.dns_source === "system_resolver"
                ? t("overview.routingDiagnostics.evidence.dnsSystem")
                : t("overview.routingDiagnostics.evidence.dnsUnknown")
        return (
          <article
            key={index}
            className="space-y-2 rounded-md border p-3 text-sm"
          >
            <h4 className="font-medium break-all">{row.options.url}</h4>
            <p>
              {row.pathLabel} ·{" "}
              {row.options.family === "ipv4" ? "IPv4" : "IPv6"} ·{" "}
              {t("overview.batch.method")}
            </p>
            <p>
              {row.state === "queued"
                ? t("overview.batch.queued")
                : row.state === "running"
                  ? t("overview.batch.running")
                  : row.state === "cancelled"
                    ? t("overview.batch.cancelled")
                    : row.state === "failed"
                      ? t("overview.batch.apiFailed")
                      : outcome === "dns"
                        ? t("overview.batch.dnsFailed")
                        : outcome === "noAddress"
                          ? t("overview.batch.noAddress")
                          : outcome === "answered"
                            ? t("overview.batch.answered", {
                                code: http?.http_status,
                              })
                            : outcome === "httpError"
                              ? t("overview.batch.httpError", {
                                  code: http?.http_status,
                                })
                              : outcome === "failed"
                                ? t("overview.batch.connectionFailed")
                                : t("overview.batch.unavailable")}
            </p>
            {http?.reason && http.ip && http.status !== "answered" ? (
              <p>{httpProbeReason(http.reason, t)}</p>
            ) : null}
            <details>
              <summary className="cursor-pointer">
                {t("overview.batch.details")}
              </summary>
              <dl className="mt-2 grid gap-2 sm:grid-cols-2">
                <div>
                  <dt>{t("overview.batch.dns")}</dt>
                  <dd className="break-all">
                    {dnsSource} · {row.response?.dns_server ?? "—"}
                    <br />
                    {row.response?.resolved_ips.join(", ") || "—"}
                    {row.response?.dns_error ? (
                      <p>{row.response.dns_error}</p>
                    ) : null}
                  </dd>
                </div>
                <div>
                  <dt>{t("overview.batch.actual")}</dt>
                  <dd className="break-all">
                    {http?.ip || "—"} / {http?.connected_ip ?? "—"} /{" "}
                    {http?.interface || "—"}
                  </dd>
                </div>
                <div>
                  <dt>{t("overview.batch.timing")}</dt>
                  <dd>
                    {t("overview.batch.timingValues", {
                      elapsed: http?.elapsed_ms ?? "—",
                      connect: http?.connect_ms ?? "—",
                      tls: http?.tls_ms ?? "—",
                      timeout: http?.timeout_ms ?? "—",
                    })}
                  </dd>
                </div>
                <div>
                  <dt>{t("overview.batch.when")}</dt>
                  <dd>
                    {row.startedAt ?? "—"}
                    <br />
                    {row.finishedAt ?? "—"}
                  </dd>
                </div>
              </dl>
              {row.error ? <p className="mt-2 break-all">{row.error}</p> : null}
              {row.response?.unapplied_draft ? (
                <p className="mt-2">
                  {t("overview.routingDiagnostics.unappliedDraft")}
                </p>
              ) : null}
              <p className="mt-2 text-muted-foreground">
                {t("overview.batch.interpretation")}
              </p>
            </details>
          </article>
        )
      })}
    </div>
  )
}

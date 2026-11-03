import { useTranslation } from "react-i18next"
import { Link } from "wouter"
import type { InterceptionHealth } from "@/api/generated/model/interceptionHealth"
import { interceptionState } from "@/lib/dns-learning"
import { useStatusEventConnectionState } from "@/api/status-event-connection"

/** Consumes the existing service-health/SSE snapshot. Viewing sends no probes. */
export function InterceptionPanel({
  health,
  configIsDraft,
}: {
  health?: InterceptionHealth
  configIsDraft: boolean
}) {
  const { t } = useTranslation()
  const connection = useStatusEventConnectionState()
  const dnsState = interceptionState(health?.dns_state)
  const l7State = interceptionState(health?.l7_state)
  return (
    <details id="learning" className="mt-4 scroll-mt-24 border-t pt-3 text-sm">
      <summary className="cursor-pointer font-medium">
        {t("learning.title")}
      </summary>
      <div className="mt-3 min-w-0 space-y-3">
        <p className="text-muted-foreground">{t("learning.observationHint")}</p>
        {connection !== "connected" && health ? (
          <p>{t("learning.staleHint")}</p>
        ) : null}
        {configIsDraft ? <p>{t("learning.draftHint")}</p> : null}
        <dl className="space-y-3">
          <div>
            <dt className="font-medium">{t("learning.dnsLabel")}</dt>
            <dd>{t(`learning.states.${dnsState}`)}</dd>
          </div>
          <div>
            <dt className="font-medium">{t("learning.l7Label")}</dt>
            <dd>{t(`learning.states.${l7State}`)}</dd>
          </div>
        </dl>
        {health ? (
          <>
            <p className="break-words">
              {t("learning.interfaces", {
                names: health.interfaces.length
                  ? health.interfaces.join(", ")
                  : "—",
              })}
            </p>
            <p>{t("learning.countersHint")}</p>
            <dl className="grid grid-cols-2 gap-2 tabular-nums">
              <div>
                <dt>{t("learning.dnsPackets")}</dt>
                <dd>{health.dns_packets}</dd>
              </div>
              <div>
                <dt>{t("learning.dnsMatched")}</dt>
                <dd>{health.dns_matched}</dd>
              </div>
              <div>
                <dt>{t("learning.l7Packets")}</dt>
                <dd>{health.l7_packets}</dd>
              </div>
              <div>
                <dt>{t("learning.l7Matched")}</dt>
                <dd>{health.l7_matched}</dd>
              </div>
              <div>
                <dt>{t("learning.setErrors")}</dt>
                <dd>{health.set_errors}</dd>
              </div>
              <div>
                <dt>{t("learning.timeouts")}</dt>
                <dd>{health.dns_hold_timeouts}</dd>
              </div>
            </dl>
            <details>
              <summary className="cursor-pointer">
                {t("learning.details")}
              </summary>
              <div className="mt-2 space-y-1 font-mono text-xs break-all">
                <p>
                  {t("learning.queueStatus", {
                    id: 43053,
                    state: health.nfqueue,
                    failOpen: health.fail_open,
                  })}
                </p>
                <p>{t("learning.logStatus", { id: 43054, state: health.nflog })}</p>
                <p>{t("learning.dnsDetail", { detail: health.dns_detail || "—" })}</p>
                <p>{t("learning.l7Detail", { detail: health.l7_detail || "—" })}</p>
                <p>
                  {t("learning.overruns", {
                    dns: health.queue_overruns,
                    l7: health.log_overruns,
                  })}
                </p>
              </div>
            </details>
          </>
        ) : null}
        <Link
          className="inline-block py-2 text-primary underline"
          href="/general#advanced"
        >
          {t("learning.settingsLink")}
        </Link>
      </div>
    </details>
  )
}

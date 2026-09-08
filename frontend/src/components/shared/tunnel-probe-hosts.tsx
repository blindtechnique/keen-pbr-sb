import { useQueryClient } from "@tanstack/react-query"
import { useRef, useState } from "react"

import { BanIcon, RefreshCwIcon, RotateCcwIcon, XIcon } from "lucide-react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"

import {
  getTunnelProbeHosts,
  updateTunnelProbeHost,
  useGetTunnelProbeHosts,
} from "@/api/generated/keen-api"
import type { TunnelProbeHostsResponse } from "@/api/generated/model/tunnelProbeHostsResponse"
import { OperationErrorMessage } from "@/components/shared/operation-error-message"
import { Button } from "@/components/ui/button"

// Контроль над тем, что автоматика уже сделала.
//
// Хост уводится в туннель по измерению, а измерение может быть право про сеть и
// не право про то, чего хочет владелец. Здесь это видно и здесь это отменяется:
// «убрать» позволяет найти хост снова, «никогда» — заносит его в отдельный
// список, который проверяется раньше пробы и раньше реестра, поэтому никакое
// новое свидетельство его не пересилит.
export function TunnelProbeHosts() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const pendingRef = useRef(false)
  const [pending, setPending] = useState(false)
  const query = useGetTunnelProbeHosts<
    Awaited<ReturnType<typeof getTunnelProbeHosts>>
  >({
    query: {
      refetchOnWindowFocus: true,
      staleTime: 30_000,
    },
  })

  const state: TunnelProbeHostsResponse | undefined =
    query.data?.status === 200 ? query.data.data : undefined

  if (!state?.available) return null

  const routed = state.routed ?? []
  const excluded = state.excluded ?? []
  const suggested = new Set(
    state.review_available === true
      ? (state.reviews ?? [])
          .filter((review) => review.suggested === true)
          .map((review) => review.host)
      : []
  )
  if (routed.length === 0 && excluded.length === 0) {
    return (
      <p className="text-[13px] text-muted-foreground">
        {t("pages.settings.general.tunnelProbeHostsEmpty")}
      </p>
    )
  }

  const act = async (
    host: string,
    action: "remove" | "exclude" | "restore",
    notifyRemoved = false
  ) => {
    if (pendingRef.current) return
    pendingRef.current = true
    setPending(true)
    try {
      const response = await updateTunnelProbeHost({ host, action })
      if (response.status !== 200) {
        throw {
          message: response.data.error,
          status: response.status,
          details: response.data,
        }
      }
      const updated = response.data
      const reflected =
        updated.available &&
        (action === "restore"
          ? Array.isArray(updated.excluded) && !updated.excluded.includes(host)
          : Array.isArray(updated.routed) &&
            !updated.routed.includes(host) &&
            (action !== "exclude" ||
              (Array.isArray(updated.excluded) &&
                updated.excluded.includes(host))))
      if (!reflected) {
        throw new Error(t("pages.settings.general.tunnelProbeHostChangeFailed"))
      }
      queryClient.setQueryData(query.queryKey, response)
      // Списки только что изменились, а панель показывает их и в других
      // местах — правило маршрутизации и сам список живут в конфигурации.
      void queryClient.invalidateQueries()
      if (notifyRemoved) {
        toast.success(t("pages.settings.general.tunnelProbeHostRemoved"))
      }
    } catch (error) {
      toast.error(
        <OperationErrorMessage
          error={error}
          fallbackSummary={t(
            "pages.settings.general.tunnelProbeHostChangeFailed"
          )}
        />,
        { richColors: true }
      )
    } finally {
      pendingRef.current = false
      setPending(false)
    }
  }

  const refresh = async () => {
    const result = await query.refetch()
    if (result.error) {
      toast.error(
        <OperationErrorMessage
          error={result.error}
          fallbackSummary={t(
            "pages.settings.general.tunnelProbeHostsRefreshFailed"
          )}
        />,
        { richColors: true }
      )
    }
  }

  return (
    <div className="space-y-3">
      {state.config_is_draft === true ? (
        <p className="text-[13px] text-muted-foreground">
          {t("pages.settings.general.tunnelProbeHostsDraftNotice")}
        </p>
      ) : null}
      <Button
        disabled={query.isFetching}
        onClick={() => void refresh()}
        size="sm"
        title={t("pages.settings.general.tunnelProbeReviewRefreshHint")}
        variant="outline"
      >
        <RefreshCwIcon className={query.isFetching ? "animate-spin" : ""} />
        {t("pages.settings.general.tunnelProbeReviewRefresh")}
      </Button>
      {state.review_available !== undefined ? (
        <p className="text-xs text-muted-foreground">
          {t("pages.settings.general.tunnelProbeReviewRefreshHint")}
        </p>
      ) : null}
      {state.review_available === false && routed.length > 0 ? (
        <p className="text-[13px] text-muted-foreground">
          {t("pages.settings.general.tunnelProbeReviewUnavailable")}
        </p>
      ) : null}
      {state.review_limited === true ? (
        <p className="text-[13px] text-muted-foreground">
          {t("pages.settings.general.tunnelProbeReviewLimited")}
        </p>
      ) : null}
      {routed.length > 0 ? (
        <div className="space-y-1">
          <p className="text-[13px] text-muted-foreground">
            {t("pages.settings.general.tunnelProbeHostsRouted")}
          </p>
          <ul className="space-y-1">
            {routed.map((host) => (
              <li className="space-y-1 text-[13px]" key={host}>
                <div className="flex items-center justify-between gap-2">
                  <span className="min-w-0 truncate">{host}</span>
                  <span className="flex shrink-0 items-center gap-1">
                    <Button
                      aria-label={t(
                        "pages.settings.general.tunnelProbeHostRemove"
                      )}
                      disabled={pending}
                      onClick={() => void act(host, "remove")}
                      size="sm"
                      title={t(
                        "pages.settings.general.tunnelProbeHostRemoveHint"
                      )}
                      variant="ghost"
                    >
                      <XIcon />
                    </Button>
                    <Button
                      aria-label={t(
                        "pages.settings.general.tunnelProbeHostExclude"
                      )}
                      disabled={pending}
                      onClick={() => void act(host, "exclude")}
                      size="sm"
                      title={t(
                        "pages.settings.general.tunnelProbeHostExcludeHint"
                      )}
                      variant="ghost"
                    >
                      <BanIcon />
                    </Button>
                  </span>
                </div>
                {suggested.has(host) ? (
                  <div className="space-y-2 rounded-md border bg-muted/40 p-3">
                    <p className="font-medium">
                      {t("pages.settings.general.tunnelProbeReviewSummary")}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {t("pages.settings.general.tunnelProbeReviewHint")}
                    </p>
                    <Button
                      disabled={pending}
                      onClick={() => void act(host, "remove", true)}
                      size="sm"
                      variant="outline"
                    >
                      {t("pages.settings.general.tunnelProbeReviewAction")}
                    </Button>
                  </div>
                ) : null}
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {excluded.length > 0 ? (
        <div className="space-y-1">
          <p className="text-[13px] text-muted-foreground">
            {t("pages.settings.general.tunnelProbeHostsExcluded")}
          </p>
          <ul className="space-y-1">
            {excluded.map((host) => (
              <li
                className="flex items-center justify-between gap-2 text-[13px]"
                key={host}
              >
                <span className="truncate text-muted-foreground">{host}</span>
                <Button
                  disabled={pending}
                  aria-label={t(
                    "pages.settings.general.tunnelProbeHostRestore"
                  )}
                  className="shrink-0"
                  onClick={() => void act(host, "restore")}
                  size="sm"
                  title={t("pages.settings.general.tunnelProbeHostRestoreHint")}
                  variant="ghost"
                >
                  <RotateCcwIcon />
                </Button>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  )
}

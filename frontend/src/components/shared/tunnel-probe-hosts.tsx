import { useQueryClient } from "@tanstack/react-query"
import { BanIcon, RotateCcwIcon, XIcon } from "lucide-react"
import { useTranslation } from "react-i18next"
import { toast } from "sonner"

import {
  getTunnelProbeHosts,
  updateTunnelProbeHost,
  useGetTunnelProbeHosts,
} from "@/api/generated/keen-api"
import type { TunnelProbeHostsResponse } from "@/api/generated/model/tunnelProbeHostsResponse"
import { Button } from "@/components/ui/button"
import { getApiErrorMessage } from "@/lib/api-errors"

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
  const query = useGetTunnelProbeHosts<
    Awaited<ReturnType<typeof getTunnelProbeHosts>>
  >({
    query: {
      refetchOnWindowFocus: false,
      staleTime: 30_000,
    },
  })

  const state: TunnelProbeHostsResponse | undefined =
    query.data?.status === 200 ? query.data.data : undefined

  if (!state?.available) return null

  const routed = state.routed ?? []
  const excluded = state.excluded ?? []
  if (routed.length === 0 && excluded.length === 0) {
    return (
      <p className="text-[13px] text-muted-foreground">
        {t("pages.settings.general.tunnelProbeHostsEmpty")}
      </p>
    )
  }

  const act = async (
    host: string,
    action: "remove" | "exclude" | "restore"
  ) => {
    try {
      await updateTunnelProbeHost({ host, action })
      await query.refetch()
      // Списки только что изменились, а панель показывает их и в других
      // местах — правило маршрутизации и сам список живут в конфигурации.
      await queryClient.invalidateQueries()
    } catch (error) {
      toast.error(getApiErrorMessage(error), { richColors: true })
    }
  }

  return (
    <div className="space-y-3">
      {routed.length > 0 ? (
        <div className="space-y-1">
          <p className="text-[13px] text-muted-foreground">
            {t("pages.settings.general.tunnelProbeHostsRouted")}
          </p>
          <ul className="space-y-1">
            {routed.map((host) => (
              <li
                className="flex items-center justify-between gap-2 text-[13px]"
                key={host}
              >
                <span className="truncate">{host}</span>
                <span className="flex shrink-0 items-center gap-1">
                  <Button
                    aria-label={t(
                      "pages.settings.general.tunnelProbeHostRemove"
                    )}
                    onClick={() => void act(host, "remove")}
                    size="sm"
                    title={t("pages.settings.general.tunnelProbeHostRemoveHint")}
                    variant="ghost"
                  >
                    <XIcon />
                  </Button>
                  <Button
                    aria-label={t(
                      "pages.settings.general.tunnelProbeHostExclude"
                    )}
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

import { useTranslation } from "react-i18next"
import { useLocation } from "wouter"

import type { ClientDnsEnforcement } from "@/api/generated/model/clientDnsEnforcement"
import { Button } from "@/components/ui/button"

export function DnsPathGuidance({
  configuration,
  configIsDraft,
}: {
  configuration: ClientDnsEnforcement | undefined
  configIsDraft: boolean
}) {
  const { t } = useTranslation()
  const [, navigate] = useLocation()

  return (
    <div className="space-y-3 text-sm">
      <p className="text-muted-foreground">
        {configuration === undefined
          ? t("overview.dnsCheck.path.configUnknown")
          : configIsDraft
            ? t("overview.dnsCheck.path.draft")
            : configuration.enabled
              ? t("overview.dnsCheck.path.enforcementOn")
              : t("overview.dnsCheck.path.enforcementOff")}
      </p>
      <details className="rounded-lg border border-border/60 p-3">
        <summary className="cursor-pointer rounded-sm text-primary focus-visible:outline-2 focus-visible:outline-ring">
          {t("overview.dnsCheck.path.helpTitle")}
        </summary>
        <div className="mt-3 space-y-3 text-muted-foreground">
          <p>{t("overview.dnsCheck.path.scope")}</p>
          <p>{t("overview.dnsCheck.path.enforcementScope")}</p>
          {configuration?.enabled && !configIsDraft ? (
            <p>
              {configuration.block_dot === false
                ? t("overview.dnsCheck.path.dotAllowed")
                : t("overview.dnsCheck.path.dotBlocked")}
            </p>
          ) : null}
          <p>{t("overview.dnsCheck.path.encryptionTradeoff")}</p>
          <ul className="list-disc space-y-3 pl-4">
            <li>
              <a
                className="text-primary underline underline-offset-2"
                href="https://support.google.com/pixelphone/answer/2819583"
                rel="noreferrer"
                target="_blank"
              >
                {t("overview.dnsCheck.path.androidTitle")}
              </a>
              <p>{t("overview.dnsCheck.path.android")}</p>
            </li>
            <li>
              <a
                className="text-primary underline underline-offset-2"
                href="https://support.google.com/chrome/answer/10468685"
                rel="noreferrer"
                target="_blank"
              >
                {t("overview.dnsCheck.path.browserTitle")}
              </a>
              <p>{t("overview.dnsCheck.path.browser")}</p>
            </li>
            <li>
              <a
                className="text-primary underline underline-offset-2"
                href="https://support.apple.com/en-us/102602"
                rel="noreferrer"
                target="_blank"
              >
                {t("overview.dnsCheck.path.appleTitle")}
              </a>
              <p>{t("overview.dnsCheck.path.apple")}</p>
            </li>
          </ul>
        </div>
      </details>
      <Button
        className="h-auto w-full text-center whitespace-normal"
        onClick={() =>
          navigate("/general?focus=client-dns-enforcement#general")
        }
        size="sm"
        variant="outline"
      >
        {t("overview.dnsCheck.path.openSettings")}
      </Button>
    </div>
  )
}

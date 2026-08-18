import { useTranslation } from "react-i18next"

import { useGetSingBoxInstallCapability } from "@/api/generated/keen-api"
import { SingBoxInstallButton } from "@/components/transports/sing-box-install-button"

/**
 * The sing-box offer inside the setup wizard.
 *
 * Shown only when sing-box is not installed. On the transports page the button
 * is always present because an operator may want to update; here the wizard is
 * a first-run flow, and a line about a dependency that is already satisfied is
 * a step they have to read past for nothing.
 */
export function SingBoxSetupOffer() {
  const { t } = useTranslation()
  const capabilityQuery = useGetSingBoxInstallCapability()
  const capability =
    capabilityQuery.data?.status === 200 ? capabilityQuery.data.data : undefined

  // Nothing measured yet, the read failed, or it is already installed: the
  // wizard says nothing. A first-run flow should not report on a dependency
  // that is in place.
  if (!capability || capability.installed_version) return null

  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border p-4">
      <div className="space-y-1">
        <p className="text-sm font-medium">
          {t("transports.singBoxInstall.setupTitle")}
        </p>
        <p className="text-muted-foreground text-sm">
          {t("transports.singBoxInstall.setupBody")}
        </p>
      </div>
      <SingBoxInstallButton />
    </div>
  )
}

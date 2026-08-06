export type DynamicTranslationUsage = Readonly<{
  /** Path relative to frontend/. */
  file: string
  /** Glob matched against the normalized source text of t()'s first argument. */
  argument: string
  /** Translation-key globs that the dynamic expression is allowed to resolve to. */
  keys: readonly string[]
  reason: string
}>

/**
 * Dynamic translation keys cannot be proven from a string literal. Every such
 * call must be declared here, next to the finite translation-key family it may
 * resolve to. `*` matches one key segment in `keys` and any text in `argument`.
 *
 * The checker fails for an undeclared dynamic call, an unused declaration, or
 * a key glob that matches no entry in the locale dictionaries. This keeps the
 * exception mechanism explicit without forcing runtime code to duplicate keys.
 */
export const dynamicTranslationUsages: readonly DynamicTranslationUsage[] = [
  {
    file: "src/components/shared/interface-picker.tsx",
    argument: "`common.interfacePicker.kinds.${*}`",
    keys: ["common.interfacePicker.kinds.*"],
    reason:
      "Kernel interface kinds are a closed union in kernel-interface-kind.ts.",
  },
  {
    file: "src/components/layout/header-health-indicator.tsx",
    argument: "`headerHealth.${*}`",
    keys: ["headerHealth.*"],
    reason: "Health tone is a closed union.",
  },
  {
    file: "src/components/layout/warning-banner-state.ts",
    argument: "`lifecycle.stages.${*}`",
    keys: ["lifecycle.stages.*"],
    reason: "Lifecycle stage ids come from the typed backend operation.",
  },
  {
    file: "src/components/layout/top-bar-controls.tsx",
    argument: "option.labelKey",
    keys: ["theme.*"],
    reason: "Theme options are a local readonly tuple.",
  },
  {
    file: "src/components/layout/top-bar-controls.tsx",
    argument: "themeOption.labelKey",
    keys: ["theme.*"],
    reason:
      "The drawer row shows the active theme name, looked up in the same tuple.",
  },
  {
    file: "src/components/layout/warning-banner.tsx",
    argument: "getWarningBannerTitleKey(*)",
    keys: ["warning.compact.*", "lifecycle.*"],
    reason: "The helper exhaustively maps WarningBannerMode to title keys.",
  },
  {
    file: "src/components/layout/warning-banner.tsx",
    argument: "getWarningBannerDescriptionKey(*)",
    keys: ["warning.compact.*", "lifecycle.*"],
    reason:
      "The helper exhaustively maps WarningBannerMode to description keys.",
  },
  {
    file: "src/components/lists/template-picker.tsx",
    argument: "`pages.listUpsert.templates.categories.${*}`",
    keys: ["pages.listUpsert.templates.categories.*"],
    reason: "Catalog categories are a closed local union.",
  },
  {
    file: "src/components/outbounds/outbound-cells.tsx",
    argument: "`overview.outbounds.status.${*}`",
    keys: ["overview.outbounds.status.*"],
    reason: "Outbound runtime status is a finite API enum.",
  },
  {
    file: "src/components/overview/active-interface-traffic.tsx",
    argument: "activeTrafficStatusTranslationKey(*)",
    keys: ["overview.outbounds.member.*"],
    reason: "The helper maps every RuntimeInterfaceStatus value.",
  },
  {
    file: "src/components/overview/outbound-state-list.tsx",
    argument: "`overview.outbounds.status.${*}`",
    keys: ["overview.outbounds.status.*"],
    reason: "Outbound runtime status is a finite API enum.",
  },
  {
    file: "src/components/overview/outbound-state-list.tsx",
    argument: "`overview.outbounds.issue.${*}`",
    keys: ["overview.outbounds.issue.*"],
    reason: "Issue codes are derived from the local typed classifier.",
  },
  {
    file: "src/components/overview/routing-diagnostics-result.tsx",
    argument: "`overview.routingDiagnostics.conditions.${*}`",
    keys: ["overview.routingDiagnostics.conditions.*"],
    reason: "Diagnostic conditions are a closed typed set.",
  },
  {
    file: "src/components/overview/services-status-card.tsx",
    argument: "dnsmasqBadge.labelKey",
    keys: ["overview.runtime.dnsmasq*"],
    reason:
      "Dnsmasq badge keys are a literal union returned by its state helper.",
  },
  {
    file: "src/components/overview/system-status-summary.tsx",
    argument: "`overview.summary.${*}.title`",
    keys: ["overview.summary.*.title"],
    reason: "Summary tone is a closed local union.",
  },
  {
    file: "src/components/overview/system-status-summary.tsx",
    argument: "`overview.summary.${*}.description`",
    keys: ["overview.summary.*.description"],
    reason: "Summary tone is a closed local union.",
  },
  {
    file: "src/components/overview/system-status-summary.tsx",
    argument: "`overview.summary.attention.${*}`",
    keys: ["overview.summary.attention.*"],
    reason: "Attention item ids are produced by the local summary builder.",
  },
  {
    file: "src/components/settings/auth-settings-card.tsx",
    argument: "authEndpointModeLabelKey(*)",
    keys: [
      "pages.settings.auth.endpointModeAuto",
      "pages.settings.auth.endpointModeManual",
    ],
    reason: "The helper maps the auto/manual endpoint-mode union.",
  },
  {
    file: "src/components/settings/logging-settings-card.tsx",
    argument: "`pages.settings.logging.levels.${*}`",
    keys: ["pages.settings.logging.levels.*"],
    reason: "Log levels are a closed local option list.",
  },
  {
    file: "src/components/shared/dependency-list.tsx",
    argument: "`common.dependencies.kind.${*}`",
    keys: ["common.dependencies.kind.*"],
    reason: "Dependency kinds are a closed local union.",
  },
  {
    file: "src/components/shared/runtime-outbound-state.tsx",
    argument: "`runtime.outboundStatus.${*}`",
    keys: ["runtime.outboundStatus.*"],
    reason: "Outbound runtime status is generated as a finite API enum.",
  },
  {
    file: "src/components/shared/schedule-picker.tsx",
    argument: "`pages.settings.autoupdate.schedule.${*}`",
    keys: [
      "pages.settings.autoupdate.schedule.hourly",
      "pages.settings.autoupdate.schedule.daily",
      "pages.settings.autoupdate.schedule.weekly",
      "pages.settings.autoupdate.schedule.monthly",
      "pages.settings.autoupdate.schedule.custom",
    ],
    reason: "Schedule presets are a closed local option list.",
  },
  {
    file: "src/components/shared/schedule-picker.tsx",
    argument: "`pages.settings.autoupdate.schedule.weekdays.${*}`",
    keys: ["pages.settings.autoupdate.schedule.weekdays.*"],
    reason: "Weekday keys are a closed local tuple.",
  },
  {
    file: "src/pages/general-config-page.tsx",
    argument: "`pages.settings.general.internalVpnServiceNames.${*}`",
    keys: ["pages.settings.general.internalVpnServiceNames.*"],
    reason: "NdmsVpnServerKind is a closed backend enum of five values.",
  },
  {
    file: "src/pages/nfqws-page.tsx",
    argument: "`nfqws.modes.${*}`",
    keys: ["nfqws.modes.*"],
    reason: "MODE_AUTO / MODE_LIST / MODE_ALL is a closed local tuple.",
  },
  {
    file: "src/pages/nfqws-page.tsx",
    argument: "`nfqws.fields.${*}.label`",
    keys: ["nfqws.fields.*.label"],
    reason: "The nfqws2.conf variables are a closed local tuple.",
  },
  {
    file: "src/pages/nfqws-page.tsx",
    argument: "`nfqws.fields.${*}.hint`",
    keys: ["nfqws.fields.*.hint"],
    reason: "The nfqws2.conf variables are a closed local tuple.",
  },
  {
    file: "src/pages/nfqws-page.tsx",
    argument: "`nfqws.fileSections.${*}`",
    keys: ["nfqws.fileSections.*"],
    reason: "The three file categories are a closed local tuple.",
  },
  {
    file: "src/pages/nfqws-page.tsx",
    argument: "`nfqws.fileEmpty.${*}`",
    keys: ["nfqws.fileEmpty.*"],
    reason: "The three file categories are a closed local tuple.",
  },
  {
    file: "src/pages/nfqws-page.tsx",
    argument: "`nfqws.fileNameDescription.${*}`",
    keys: ["nfqws.fileNameDescription.*"],
    reason: "The three file categories are a closed local tuple.",
  },
  {
    file: "src/components/transports/native-interface-details.tsx",
    argument: "`transports.nativeInterface.managementBlockers.${*}`",
    keys: ["transports.nativeInterface.managementBlockers.*"],
    reason: "Management blockers are a finite backend enum.",
  },
  {
    file: "src/components/transports/sing-box-process-mode-dialog.tsx",
    argument: "`transports.processMode.modes.${*}.label`",
    keys: ["transports.processMode.modes.*.label"],
    reason: "Process modes are a closed local tuple.",
  },
  {
    file: "src/components/transports/sing-box-process-mode-dialog.tsx",
    argument: "`transports.processMode.modes.${*}.description`",
    keys: ["transports.processMode.modes.*.description"],
    reason: "Process modes are a closed local tuple.",
  },
  {
    file: "src/components/transports/transport-config-dialog.tsx",
    argument: "`transports.form.geo.${*}`",
    keys: ["transports.form.geo.*"],
    reason: "Geo modes are a closed local tuple.",
  },
  {
    file: "src/pages/catalog-page.tsx",
    argument: "`pages.catalog.categories.${*}`",
    keys: ["pages.catalog.categories.*"],
    reason: "Catalog categories are a closed local union.",
  },
  {
    file: "src/pages/general-config-page.tsx",
    argument: "`pages.settings.general.strictEnforcementOptions.${*}`",
    keys: ["pages.settings.general.strictEnforcementOptions.*"],
    reason: "Strict-enforcement modes are a finite config enum.",
  },
  {
    file: "src/pages/general-config-page.tsx",
    argument: "`pages.settings.general.strictEnforcementHints.${*}`",
    keys: ["pages.settings.general.strictEnforcementHints.*"],
    reason: "Strict-enforcement modes are a finite config enum.",
  },
  {
    file: "src/pages/list-upsert-page.tsx",
    argument: "`pages.listUpsert.sourceGroups.${*}.button`",
    keys: ["pages.listUpsert.sourceGroups.*.button"],
    reason: "Source groups are a closed local tuple.",
  },
  {
    file: "src/pages/list-upsert-page.tsx",
    argument: "`pages.listUpsert.refreshRoute.${*}Hint`",
    keys: [
      "pages.listUpsert.refreshRoute.inheritHint",
      "pages.listUpsert.refreshRoute.overrideHint",
    ],
    reason: "Refresh-route mode is an inherit/override union.",
  },
  {
    file: "src/pages/lists-page.tsx",
    argument: "`pages.lists.source.${*}`",
    keys: ["pages.lists.source.*"],
    reason: "List source labels come from a closed local classifier.",
  },
  {
    file: "src/pages/nfqws-page.tsx",
    argument: "`nfqws.tabs.${*}`",
    keys: ["nfqws.tabs.*"],
    reason: "nfqws tabs are a closed local tuple.",
  },
  {
    file: "src/pages/outbounds-page.tsx",
    argument: "`pages.outbounds.groups.${*}`",
    keys: ["pages.outbounds.groups.*"],
    reason: "Outbound groups are produced by a closed local classifier.",
  },
  {
    file: "src/pages/outbounds-page.tsx",
    argument: "`pages.outbounds.groupsEmpty.${*}`",
    keys: ["pages.outbounds.groupsEmpty.*"],
    reason: "Outbound groups are produced by a closed local classifier.",
  },
  {
    file: "src/pages/outbound-upsert-page.tsx",
    argument: "`pages.outboundUpsert.fields.typeOptions.${*}`",
    keys: ["pages.outboundUpsert.fields.typeOptions.*"],
    reason: "Outbound type is a finite config enum.",
  },
  {
    file: "src/pages/outbound-upsert-page.tsx",
    argument: "`pages.outboundUpsert.urltest.selectionModeOptions.${*}`",
    keys: ["pages.outboundUpsert.urltest.selectionModeOptions.*"],
    reason: "URL-test selection modes are a closed local tuple.",
  },
  {
    file: "src/pages/outbound-upsert-page.tsx",
    argument: "`pages.outboundUpsert.urltest.selectionModeHints.${*}`",
    keys: ["pages.outboundUpsert.urltest.selectionModeHints.*"],
    reason: "URL-test selection modes are a closed local tuple.",
  },
  {
    file: "src/pages/outbound-upsert-page.tsx",
    argument: "`pages.outboundUpsert.urltest.conntrackOnSwitchOptions.${*}`",
    keys: ["pages.outboundUpsert.urltest.conntrackOnSwitchOptions.*"],
    reason: "Conntrack switch policies are a finite config enum.",
  },
  {
    file: "src/pages/outbound-upsert-page.tsx",
    argument: "`pages.outboundUpsert.urltest.conntrackOnSwitchHints.${*}`",
    keys: ["pages.outboundUpsert.urltest.conntrackOnSwitchHints.*"],
    reason: "Conntrack switch policies are a finite config enum.",
  },
  {
    file: "src/pages/outbound-upsert-page.tsx",
    argument: "`pages.outboundUpsert.strictEnforcement.explanations.${*}`",
    keys: ["pages.outboundUpsert.strictEnforcement.explanations.*"],
    reason: "Kill-switch overrides are a finite config enum.",
  },
  {
    file: "src/components/transports/transport-config-dialog.tsx",
    argument: "`pages.outboundUpsert.strictEnforcement.explanations.${*}`",
    keys: ["pages.outboundUpsert.strictEnforcement.explanations.*"],
    reason:
      "The tunnel form edits the linked route's kill-switch with the same finite enum and wording.",
  },
  {
    file: "src/components/settings/backup-dialogs.tsx",
    argument: "warningKey",
    keys: ["pages.settings.backup.pairWarnings.*"],
    reason:
      "Backup pair warnings are a finite list assembled from BACKUP_PAIR_WARNINGS.",
  },
  {
    file: "src/pages/transport-upsert-page.tsx",
    argument: "`transports.configMessages.${*}`",
    keys: ["transports.configMessages.*"],
    reason: "Transport mutations use a finite operation union.",
  },
  {
    file: "src/pages/transports-page.tsx",
    argument: "`transports.configMessages.${*}`",
    keys: ["transports.configMessages.*"],
    reason: "Transport mutations use a finite operation union.",
  },
  {
    file: "src/pages/transports-page.tsx",
    argument: "`transports.states.${*}`",
    keys: ["transports.states.*"],
    reason: "Transport state is a finite API enum.",
  },
  {
    file: "src/components/settings/backup-dialogs.tsx",
    argument: "groupLabelKey(group)",
    keys: ["pages.settings.backup.groups.*"],
    reason: "Backup groups are a finite API enum (BackupGroup).",
  },
] as const

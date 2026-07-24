export type SettingsSectionState = {
  dirty: boolean
  valid: boolean
}

export type SettingsSectionController = {
  reset: () => void
  save: () => Promise<void>
}

export const CLEAN_SETTINGS_SECTION_STATE: SettingsSectionState = {
  dirty: false,
  valid: true,
}

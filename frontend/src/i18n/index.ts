import i18n from "i18next"
import { initReactI18next } from "react-i18next"

export type Language = "en" | "ru"

export const DEFAULT_LANGUAGE: Language = "en"
export const LANGUAGE_STORAGE_KEY = "language"

const LANGUAGE_VALUES: Language[] = ["en", "ru"]

/**
 * Словари грузятся по одному.
 *
 * Оба лежали в главном чанке статически: 172 КБ из 392 КБ, при том что i18next
 * показывает ровно один. Второй язык — отдельный чанк, который скачивается
 * только когда его выбирают.
 */
const bundleLoaders: Record<Language, () => Promise<object>> = {
  en: () => import("./en").then((module) => module.enTranslation),
  ru: () => import("./ru").then((module) => module.ruTranslation),
}

export function isLanguage(value: string | null): value is Language {
  if (value === null) {
    return false
  }

  return LANGUAGE_VALUES.includes(value as Language)
}

export function detectInitialLanguage(): Language {
  if (typeof window !== "undefined") {
    const storedLanguage = window.localStorage.getItem(LANGUAGE_STORAGE_KEY)
    if (isLanguage(storedLanguage)) {
      return storedLanguage
    }
  }

  if (typeof navigator === "undefined") {
    return DEFAULT_LANGUAGE
  }

  const preferred = navigator.languages?.[0] ?? navigator.language
  if (!preferred) {
    return DEFAULT_LANGUAGE
  }

  return preferred.toLowerCase().startsWith("ru") ? "ru" : DEFAULT_LANGUAGE
}

/** Догрузить словарь, если его ещё нет. Повторный вызов ничего не стоит. */
export async function ensureLanguageBundle(language: Language): Promise<void> {
  if (i18n.hasResourceBundle(language, "translation")) {
    return
  }

  const bundle = await bundleLoaders[language]()
  i18n.addResourceBundle(language, "translation", bundle, true, true)
}

/**
 * Инициализация до первого рендера: без словаря интерфейс покажет ключи.
 *
 * `fallbackLng` указывает на сам загруженный язык, а не на английский:
 * запасного словаря в памяти может не быть, а наборы ключей у языков совпадают
 * — это проверяет `bun run i18n:check` на каждой сборке.
 */
export async function initI18n(): Promise<typeof i18n> {
  const language = detectInitialLanguage()
  const bundle = await bundleLoaders[language]()

  await i18n.use(initReactI18next).init({
    resources: { [language]: { translation: bundle } },
    lng: language,
    fallbackLng: language,
    interpolation: { escapeValue: false },
  })

  return i18n
}

export default i18n

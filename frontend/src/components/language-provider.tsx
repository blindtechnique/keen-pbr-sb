/* eslint-disable react-refresh/only-export-components */
import * as React from "react"

import i18n, {
  DEFAULT_LANGUAGE,
  ensureLanguageBundle,
  isLanguage,
  LANGUAGE_STORAGE_KEY,
  type Language,
} from "@/i18n"
import {
  safeStorageGet,
  safeStorageMatches,
  safeStorageSet,
} from "@/lib/safe-storage"

type LanguageProviderProps = {
  children: React.ReactNode
  defaultLanguage?: Language
  storageKey?: string
}

type LanguageProviderState = {
  language: Language
  setLanguage: (language: Language) => void
}

const LanguageProviderContext = React.createContext<
  LanguageProviderState | undefined
>(undefined)

export function LanguageProvider({
  children,
  defaultLanguage = DEFAULT_LANGUAGE,
  storageKey = LANGUAGE_STORAGE_KEY,
  ...props
}: LanguageProviderProps) {
  const [language, setLanguageState] = React.useState<Language>(() => {
    const storedLanguage = safeStorageGet(() => window.localStorage, storageKey)
    if (isLanguage(storedLanguage)) {
      return storedLanguage
    }

    const currentLanguage = i18n.resolvedLanguage ?? i18n.language
    if (isLanguage(currentLanguage)) {
      return currentLanguage
    }

    return defaultLanguage
  })

  const setLanguage = React.useCallback(
    (nextLanguage: Language) => {
      safeStorageSet(() => window.localStorage, storageKey, nextLanguage)
      setLanguageState(nextLanguage)
    },
    [storageKey]
  )

  React.useEffect(() => {
    if (i18n.resolvedLanguage === language) {
      return
    }

    // Словарь второго языка приезжает отдельным чанком — сначала он, потом
    // переключение, иначе на кадр покажутся ключи.
    void ensureLanguageBundle(language).then(() =>
      i18n.changeLanguage(language)
    )
  }, [language])

  React.useEffect(() => {
    const handleLanguageChanged = (nextLanguage: string) => {
      if (!isLanguage(nextLanguage)) {
        return
      }

      setLanguageState(nextLanguage)
      safeStorageSet(() => window.localStorage, storageKey, nextLanguage)
    }

    i18n.on("languageChanged", handleLanguageChanged)

    return () => {
      i18n.off("languageChanged", handleLanguageChanged)
    }
  }, [storageKey])

  React.useEffect(() => {
    const handleStorageChange = (event: StorageEvent) => {
      if (!safeStorageMatches(() => window.localStorage, event.storageArea)) {
        return
      }

      if (event.key !== storageKey) {
        return
      }

      if (isLanguage(event.newValue)) {
        setLanguageState(event.newValue)
        return
      }

      setLanguageState(defaultLanguage)
    }

    window.addEventListener("storage", handleStorageChange)

    return () => {
      window.removeEventListener("storage", handleStorageChange)
    }
  }, [defaultLanguage, storageKey])

  const value = React.useMemo(
    () => ({
      language,
      setLanguage,
    }),
    [language, setLanguage]
  )

  return (
    <LanguageProviderContext.Provider {...props} value={value}>
      {children}
    </LanguageProviderContext.Provider>
  )
}

export const useLanguage = () => {
  const context = React.useContext(LanguageProviderContext)

  if (context === undefined) {
    throw new Error("useLanguage must be used within a LanguageProvider")
  }

  return context
}

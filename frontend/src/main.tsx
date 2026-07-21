import { StrictMode } from "react"
import { createRoot } from "react-dom/client"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"

// The panel is Russian/English. Loading every Roboto unicode subset emitted
// dozens of unused font files into the IPK; keep only the two scripts we use.
import "@fontsource/roboto/cyrillic-400.css"
import "@fontsource/roboto/cyrillic-500.css"
import "@fontsource/roboto/cyrillic-700.css"
import "@fontsource/roboto/latin-400.css"
import "@fontsource/roboto/latin-500.css"
import "@fontsource/roboto/latin-700.css"
import "./index.css"
import "./i18n"
import { LanguageProvider } from "@/components/language-provider"
import App from "./App.tsx"
import { ThemeProvider } from "@/components/theme-provider.tsx"
import { Toaster } from "@/components/ui/sonner"
import { TooltipProvider } from "@/components/ui/tooltip"

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      gcTime: 5 * 60_000,
      retry: (failureCount, error) => {
        const status =
          typeof error === "object" &&
          error !== null &&
          "status" in error &&
          typeof (error as { status?: unknown }).status === "number"
            ? (error as { status: number }).status
            : null

        if (status !== null && status >= 400 && status < 500) {
          return false
        }

        return failureCount < 2
      },
    },
  },
})

const toasterBottomOffset =
  "calc(var(--warning-banner-height, 0px) + env(safe-area-inset-bottom, 0px) + 1rem)"

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <LanguageProvider>
          <ThemeProvider>
            <App />
            <Toaster
              offset={{ bottom: toasterBottomOffset }}
              mobileOffset={{ bottom: toasterBottomOffset }}
            />
          </ThemeProvider>
        </LanguageProvider>
      </TooltipProvider>
    </QueryClientProvider>
  </StrictMode>
)

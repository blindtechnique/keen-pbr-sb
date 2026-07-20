import { useEffect } from "react"
import { useLocation } from "wouter"

export function ScrollToTopOnRouteChange() {
  const [pathname] = useLocation()

  useEffect(() => {
    // The content area scrolls now, not the document, so scrolling the window
    // does nothing and a new page opened wherever the last one was left.
    const main = document.getElementById("main-content")
    if (main) {
      main.scrollTo({ top: 0, left: 0, behavior: "auto" })
      return
    }
    window.scrollTo({ top: 0, left: 0, behavior: "auto" })
  }, [pathname])

  return null
}

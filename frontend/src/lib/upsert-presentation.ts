export function buildAdvancedEditorHref(location: string, search: string) {
  const [pathname, inlineSearch = ""] = location.split("?", 2)
  const params = new URLSearchParams(
    (inlineSearch || search).replace(/^\?/, "")
  )
  params.set("view", "page")

  return `${pathname}?${params.toString()}`
}

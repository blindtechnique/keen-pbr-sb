export const transportCreateHref = "/transports/create"

const NATIVE_INTERFACE_QUERY = "nativeInterface"

export function buildNativeTransportCreateHref(interfaceName: string) {
  const params = new URLSearchParams({
    [NATIVE_INTERFACE_QUERY]: interfaceName,
  })
  return `${transportCreateHref}?${params.toString()}`
}

export function readNativeTransportCreateInterface(search: string) {
  const interfaceName = new URLSearchParams(search.replace(/^\?/, ""))
    .get(NATIVE_INTERFACE_QUERY)
    ?.trim()

  return interfaceName || undefined
}

export function buildTransportEditHref(tag: string) {
  return `/transports/${encodeURIComponent(tag)}/edit`
}

export const transportCreateHref = "/transports/create"

export function buildTransportEditHref(tag: string) {
  return `/transports/${encodeURIComponent(tag)}/edit`
}

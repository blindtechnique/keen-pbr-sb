export const META_UDP_443_POLICIES = ["balanced", "messages_first"] as const

export type MetaUdp443Policy = (typeof META_UDP_443_POLICIES)[number]

export function getMetaUdp443Policy(daemon: unknown): MetaUdp443Policy {
  if (!daemon || typeof daemon !== "object") {
    return "balanced"
  }

  return (daemon as { meta_udp443_policy?: unknown }).meta_udp443_policy ===
    "messages_first"
    ? "messages_first"
    : "balanced"
}

/**
 * `balanced` is the backend default. Keep it absent from the document so an
 * unchanged configuration stays compatible with builds that predate the
 * explicit transport policy.
 */
export function withMetaUdp443Policy<T extends object>(
  daemon: T,
  policy: MetaUdp443Policy
): T & { meta_udp443_policy?: MetaUdp443Policy } {
  const updated = { ...daemon } as T & {
    meta_udp443_policy?: MetaUdp443Policy
  }

  if (policy === "balanced") {
    delete updated.meta_udp443_policy
  } else {
    updated.meta_udp443_policy = policy
  }

  return updated
}

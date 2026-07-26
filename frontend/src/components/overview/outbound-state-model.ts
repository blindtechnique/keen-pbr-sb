import type { Outbound } from "@/api/generated/model"

export function outboundTrafficBucket(
  outbound: Pick<Outbound, "type">,
  protocol: string
): "tunnels" | "direct" | "blocked" {
  if (outbound.type === "blackhole") {
    return "blocked"
  }
  return protocol ? "tunnels" : "direct"
}

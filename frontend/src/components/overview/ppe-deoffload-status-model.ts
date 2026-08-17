import type { PpeDeoffloadHealth } from "@/api/generated/model"

export type PpeDeoffloadBadgeVariant =
  | "success"
  | "warning"
  | "destructive"
  | "outline"

export type PpeDeoffloadPresentation = {
  kind:
    | "verifiedActive"
    | "admissibleOnly"
    | "degraded"
    | "inactive"
    | "off"
    | "unknown"
  badgeVariant: PpeDeoffloadBadgeVariant
}

/**
 * Convert the backend state into UI semantics without collapsing
 * `admissible` into `active`. Passing the capability gates only says that a
 * reconcile may proceed; only a semantically verified live graph is active.
 */
export function getPpeDeoffloadPresentation(
  health: PpeDeoffloadHealth
): PpeDeoffloadPresentation {
  switch (health.state) {
    case "active":
      return { kind: "verifiedActive", badgeVariant: "success" }
    case "admissible":
      return { kind: "admissibleOnly", badgeVariant: "warning" }
    case "degraded":
      return { kind: "degraded", badgeVariant: "destructive" }
    case "inactive":
      return { kind: "inactive", badgeVariant: "outline" }
    case "off":
      return { kind: "off", badgeVariant: "outline" }
    default:
      return { kind: "unknown", badgeVariant: "warning" }
  }
}

export function formatPpePorts(ports: string[]) {
  return ports.length > 0 ? ports.join(", ") : null
}

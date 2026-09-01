import type { Dependency } from "@/lib/dependencies"

const VISIBLE_NATIVE_DELETE_DEPENDENCIES = 3

export type NativeDeleteDependencySummary = Readonly<{
  labels: string[]
  remainingCount: number
}>

/** Keep the pre-delete warning useful without turning a toast into a report. */
export function summarizeNativeDeleteDependencies(
  dependencies: readonly Dependency[]
): NativeDeleteDependencySummary {
  const labels = [
    ...new Set(
      dependencies
        .map((dependency) => dependency.label.trim())
        .filter((label) => label.length > 0)
    ),
  ]

  return {
    labels: labels.slice(0, VISIBLE_NATIVE_DELETE_DEPENDENCIES),
    remainingCount: Math.max(
      0,
      labels.length - VISIBLE_NATIVE_DELETE_DEPENDENCIES
    ),
  }
}

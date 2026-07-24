import { cn } from "@/lib/utils"

export function KeeneticMenuIcon({ className }: { className?: string }) {
  return (
    <svg
      aria-hidden="true"
      className={cn("size-6", className)}
      fill="none"
      viewBox="0 0 24 24"
    >
      <path
        d="M-.1 20v.1H24.1v-2.867H-.1V20Zm0-6.667v.1H24.1v-2.866H-.1v2.766ZM0 3.9h-.1v2.867H24.1V3.9H0Z"
        fill="currentColor"
        stroke="currentColor"
        strokeWidth=".2"
      />
    </svg>
  )
}

export function KeeneticMenuArrowIcon({ className }: { className?: string }) {
  return (
    <svg
      aria-hidden="true"
      className={cn("size-5", className)}
      fill="none"
      viewBox="0 0 20 20"
    >
      <path
        d="M18 9.563H6.59l5.241-5.241L10.5 3 3 10.5l7.5 7.5 1.322-1.322-5.231-5.24H18V9.562Z"
        fill="currentColor"
      />
    </svg>
  )
}

export function KeeneticCloseIcon({ className }: { className?: string }) {
  return (
    <svg
      aria-hidden="true"
      className={cn("size-6", className)}
      fill="none"
      viewBox="0 0 12 12"
    >
      <path
        d="M12 1.209 10.791 0 6 4.791 1.209 0 0 1.209 4.791 6 0 10.791 1.209 12 6 7.209 10.791 12 12 10.791 7.209 6 12 1.209Z"
        fill="currentColor"
      />
    </svg>
  )
}

import { Switch as SwitchPrimitive } from "@base-ui/react/switch"

import { cn } from "@/lib/utils"

/**
 * Цвета переключателя живут в index.css, а не здесь.
 *
 * Их четыре набора — включён, выключен, светлая тема, тёмная, — и к каждому
 * добавляется наведение, которое должно срабатывать только когда нажать
 * действительно можно. Условие «наведён и не выключен» утилитами Tailwind
 * выражается плохо, зато обычным `:hover:not([data-disabled])` — точно.
 * Здесь остаётся только геометрия.
 */
function Switch({
  className,
  size = "default",
  ...props
}: SwitchPrimitive.Root.Props & {
  size?: "sm" | "default"
}) {
  return (
    <SwitchPrimitive.Root
      data-slot="switch"
      data-size={size}
      className={cn(
        "peer group/switch relative inline-flex shrink-0 items-center border-0 bg-transparent p-0 transition-all outline-none after:absolute after:-inset-x-3 after:-inset-y-2 focus-visible:ring-3 focus-visible:ring-ring/50 aria-invalid:ring-3 aria-invalid:ring-destructive/20 data-[size=default]:h-5 data-[size=default]:w-[34px] data-[size=sm]:h-4 data-[size=sm]:w-7 dark:aria-invalid:ring-destructive/40 data-disabled:cursor-not-allowed data-disabled:opacity-50",
        className
      )}
      {...props}
    >
      <span
        aria-hidden="true"
        className="pointer-events-none absolute top-1/2 left-1/2 h-3.5 w-full -translate-x-1/2 -translate-y-1/2 rounded-full border border-transparent transition-colors group-data-[size=sm]/switch:h-2.5"
        data-slot="switch-track"
      />
      <SwitchPrimitive.Thumb
        data-slot="switch-thumb"
        className="pointer-events-none relative z-10 block rounded-full ring-0 transition-[transform,background-color,box-shadow] duration-100 group-data-[size=default]/switch:size-5 group-data-[size=sm]/switch:size-4 group-data-unchecked/switch:-translate-x-px group-data-[size=default]/switch:data-checked:translate-x-[14px] group-data-[size=sm]/switch:data-checked:translate-x-3"
      />
    </SwitchPrimitive.Root>
  )
}

export { Switch }

import * as React from "react"
import { Input as InputPrimitive } from "@base-ui/react/input"

import { cn } from "@/lib/utils"

/**
 * Размер поля — как у Select: 40px по умолчанию, 32px в строке с кнопками.
 *
 * Кнопка в этом интерфейсе — 32px, а поле было единственным элементом с одной
 * жёстко зашитой высотой. Поэтому везде, где поиск или ввод стоят рядом с
 * кнопкой, они расходились на восемь пикселей.
 */
function Input({
  className,
  size = "default",
  type,
  ...props
}: Omit<React.ComponentProps<"input">, "size"> & { size?: "sm" | "default" }) {
  return (
    <InputPrimitive
      type={type}
      data-slot="input"
      data-size={size}
      className={cn(
        "w-full min-w-0 rounded-[4px] border border-input bg-card px-3 py-2 text-sm shadow-[inset_0_1px_1px_rgb(20_45_58_/_0.03)] transition-colors outline-none file:inline-flex file:h-6 file:border-0 file:bg-transparent file:text-sm file:font-medium file:text-foreground placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/20 disabled:pointer-events-none disabled:cursor-not-allowed disabled:border-[#BDB7B7] disabled:bg-muted disabled:opacity-60 aria-invalid:border-destructive aria-invalid:ring-3 aria-invalid:ring-destructive/20 data-[size=default]:h-10 data-[size=sm]:h-8 dark:bg-card dark:disabled:border-input dark:disabled:bg-muted dark:aria-invalid:border-destructive/50 dark:aria-invalid:ring-destructive/40",
        className
      )}
      {...props}
    />
  )
}

export { Input }

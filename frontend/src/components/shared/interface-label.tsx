import { useInterfaceNames } from "@/hooks/use-interface-names"
import { cn } from "@/lib/utils"

/**
 * Имя интерфейса так, как его назвал владелец роутера.
 *
 * Маршрутизация работает в именах ядра, и обойтись без них нельзя, но никто не
 * выбирал «nwg2» — в NDMS этот интерфейс назван «sddvpn.mooo.com AWG2». Там,
 * где имя из прошивки известно, показываем его, а имя ядра оставляем во
 * всплывающей подсказке: оно нужно редко, но когда нужно — нужно точно.
 *
 * Если прошивка недоступна (OpenWrt, старая NDMS, выключенный RCI), всё
 * молча остаётся как было. Это украшение, а не зависимость.
 */
export function InterfaceLabel({
  name,
  className,
}: {
  name?: string | null
  className?: string
}) {
  const { labelFor } = useInterfaceNames()

  if (!name) {
    return null
  }

  const label = labelFor(name)
  const isKernelName = label === name

  return (
    <span
      className={cn(
        "text-xs text-muted-foreground",
        // Моноширинным набирается только техническое имя. Человеческое
        // название — обычный текст, иначе оно выглядит как код.
        isKernelName && "font-mono",
        className
      )}
      title={isKernelName ? undefined : name}
    >
      {label}
    </span>
  )
}

import { cn } from "@/lib/utils"

/**
 * Индикатор загрузки KeeneticOS.
 *
 * Восемь лучей по кругу с нарастающей прозрачностью, вращаются шагами — тот
 * самый, что прошивка показывает при переходе между страницами. Геометрия
 * снята со скриншота живого конфигуратора попиксельно: внешний радиус 67.5px,
 * внутренний 34, толщина луча 8.7 — то есть в поле 64px это луч 4×16 от
 * радиуса 16 до 32.
 *
 * Зачем он вместо скелетона: скелетон отвечает на вопрос «что здесь будет», а
 * при переходе между страницами вопрос другой — «оно вообще грузится или
 * зависло». Вращение отвечает на него без слов, скелетон — нет.
 */
const SPOKES = Array.from({ length: 8 }, (_, index) => ({
  angle: index * 45,
  // Замеренный разброс — от почти невидимого хвоста до полного цвета головы.
  opacity: Number((0.1 + index * 0.1286).toFixed(3)),
}))

export function KeenSpinner({
  className,
  label,
}: {
  className?: string
  /** Текст для читалки с экрана: «Загрузка страницы». */
  label: string
}) {
  return (
    <span
      aria-label={label}
      className={cn("keen-spinner", className)}
      role="status"
    >
      <svg aria-hidden="true" viewBox="0 0 64 64">
        {SPOKES.map((spoke) => (
          <rect
            height="16"
            key={spoke.angle}
            opacity={spoke.opacity}
            rx="2"
            transform={`rotate(${spoke.angle} 32 32)`}
            width="4"
            x="30"
            y="0"
          />
        ))}
      </svg>
    </span>
  )
}

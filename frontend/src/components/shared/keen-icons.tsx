import type { SVGProps } from "react"

/**
 * Карандаш из конфигуратора KeeneticOS, а не из набора lucide.
 *
 * Взят из спрайта прошивки (`assets/sprite/sprite.svg#pencil`): контур
 * 16×16, одна заливка `currentColor`, без обводки. Разница с lucide видна
 * рядом: у lucide это линия толщиной 2 px в сетке 24×24, у прошивки —
 * сплошная фигура в сетке 16×16, поэтому при одном и том же размере
 * прошивочный выглядит плотнее и мельче.
 *
 * Размер по умолчанию тоже прошивочный: 16×16. В конфигураторе значок
 * действия в строке таблицы именно такой, а область нажатия вокруг него
 * больше самого значка.
 */
export function KeenPencilIcon({
  className,
  ...props
}: SVGProps<SVGSVGElement>) {
  return (
    <svg
      aria-hidden="true"
      className={className}
      fill="currentColor"
      focusable="false"
      height="16"
      viewBox="0 0 16 16"
      width="16"
      xmlns="http://www.w3.org/2000/svg"
      {...props}
    >
      <path d="m9.83 5.35.817.818-8.052 8.052h-.817v-.817L9.83 5.35ZM13.03 0a.89.89 0 0 0-.623.258l-1.626 1.626 3.333 3.333 1.626-1.626a.885.885 0 0 0 0-1.254L13.66.257A.873.873 0 0 0 13.03 0Zm-3.2 2.835L0 12.665v3.333h3.333l9.83-9.83L9.83 2.835Z" />
    </svg>
  )
}

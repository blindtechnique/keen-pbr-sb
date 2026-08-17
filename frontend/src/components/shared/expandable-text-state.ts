/**
 * Решения `ExpandableText`, вынесенные из компонента, чтобы их можно было
 * проверить тестом.
 *
 * Ограничение по числу строк делает Tailwind-класс `line-clamp-N`. Собрать его
 * из переменной нельзя: сборщик ищет классы по исходному тексту и не увидит
 * `` `line-clamp-${lines}` ``, поэтому правило просто не попадёт в CSS. Внешне
 * это выглядит как «компонент не работает», а не как отсутствующий класс —
 * ошибка молчаливая, поэтому список классов записан буквально и закрыт тестом.
 */
const CLAMP_CLASS_NAMES = {
  1: "line-clamp-1",
  2: "line-clamp-2",
  3: "line-clamp-3",
  4: "line-clamp-4",
} as const

export type ExpandableTextLines = keyof typeof CLAMP_CLASS_NAMES

export const EXPANDABLE_TEXT_LINE_OPTIONS = Object.keys(CLAMP_CLASS_NAMES).map(
  Number
) as readonly ExpandableTextLines[]

export function clampClassName(lines: ExpandableTextLines): string {
  return CLAMP_CLASS_NAMES[lines]
}

/**
 * Кнопка нужна не только когда текст не поместился.
 *
 * Развёрнутый текст помещается по определению, поэтому измерение переполнения
 * в этот момент даёт «нет», и кнопка «Свернуть» исчезала бы сразу после
 * первого нажатия — развернуть можно, свернуть нельзя.
 */
export function shouldShowToggle(overflows: boolean, expanded: boolean) {
  return overflows || expanded
}

import { describe, expect, it } from "bun:test"

import {
  clampClassName,
  EXPANDABLE_TEXT_LINE_OPTIONS,
  shouldShowToggle,
} from "../src/components/shared/expandable-text-state"

describe("clampClassName", () => {
  // Класс собирается не из переменной именно потому, что сборщик Tailwind ищет
  // классы по исходному тексту. Тест ловит обратную правку: стоит записать
  // `line-clamp-${lines}`, и ограничение по строкам тихо перестанет работать,
  // а компонент внешне останется целым.
  it("returns a literal utility class for every supported line count", () => {
    for (const lines of EXPANDABLE_TEXT_LINE_OPTIONS) {
      expect(clampClassName(lines)).toBe(`line-clamp-${lines}`)
    }
  })

  it("covers the line counts the component offers", () => {
    expect([...EXPANDABLE_TEXT_LINE_OPTIONS]).toEqual([1, 2, 3, 4])
  })
})

describe("shouldShowToggle", () => {
  it("shows the control when the collapsed text does not fit", () => {
    expect(shouldShowToggle(true, false)).toBe(true)
  })

  it("hides the control when the whole text already fits", () => {
    expect(shouldShowToggle(false, false)).toBe(false)
  })

  // Развёрнутый текст помещается по определению, поэтому измерение
  // переполнения даёт «нет». Без этого правила кнопка «Свернуть» исчезала бы
  // сразу после раскрытия, и свернуть текст было бы нечем.
  it("keeps the control while the text is expanded", () => {
    expect(shouldShowToggle(false, true)).toBe(true)
  })
})

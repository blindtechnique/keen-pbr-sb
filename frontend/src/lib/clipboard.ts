/**
 * Копирование в буфер обмена.
 *
 * `navigator.clipboard` существует только в защищённом контексте, а панель
 * открывается по обычному http на локальном адресе. Поэтому запасной путь через
 * `execCommand("copy")` обязателен: это не поддержка старых браузеров, а
 * основной путь для половины наших пользователей.
 */
export async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text)
      return true
    }
  } catch {
    // Падаем в execCommand: в незащищённом контексте Clipboard API либо
    // отсутствует, либо отклоняет запись.
  }

  return copyWithExecCommand(text)
}

function copyWithExecCommand(text: string): boolean {
  const textarea = document.createElement("textarea")
  textarea.value = text
  textarea.setAttribute("readonly", "")
  textarea.style.position = "fixed"
  textarea.style.top = "0"
  textarea.style.left = "0"
  textarea.style.opacity = "0"

  document.body.appendChild(textarea)
  textarea.focus()
  textarea.select()

  try {
    return document.execCommand("copy")
  } catch {
    return false
  } finally {
    document.body.removeChild(textarea)
  }
}

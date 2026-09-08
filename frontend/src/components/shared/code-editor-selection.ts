export type CodeEditorSelection = Readonly<{
  value: string
  line: number
  start: number
  end: number
}>

// A selection is requested once after a failed submit, not on each render.
// The value check prevents a late response from moving the caret in newer input.
export function focusCodeEditorSelection(
  textarea: HTMLTextAreaElement | null,
  highlight: HTMLPreElement | null,
  selection: CodeEditorSelection
): boolean {
  if (!textarea || !highlight || textarea.value !== selection.value)
    return false
  textarea.focus({ preventScroll: true })
  textarea.setSelectionRange(selection.start, selection.end)
  textarea.scrollIntoView({ block: "center" })
  const line = highlight.children.item(selection.line - 1)
  if (line) {
    const rect = line.getBoundingClientRect()
    // Existing highlighted spans already account for soft wraps and font size.
    const top =
      rect.top - highlight.getBoundingClientRect().top + highlight.scrollTop
    textarea.scrollTop = Math.max(
      0,
      top + rect.height / 2 - textarea.clientHeight / 2
    )
    highlight.scrollTop = textarea.scrollTop
  }
  return true
}

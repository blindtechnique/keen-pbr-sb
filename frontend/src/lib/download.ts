export function formatDownloadTimestamp(date = new Date()): string {
  const pad = (value: number) => String(value).padStart(2, "0")
  return [
    date.getFullYear(),
    pad(date.getMonth() + 1),
    pad(date.getDate()),
    pad(date.getHours()),
    pad(date.getMinutes()),
    pad(date.getSeconds()),
  ].join("-")
}

export function downloadJson(filename: string, value: unknown): void {
  const url = URL.createObjectURL(
    new Blob([`${JSON.stringify(value, null, 2)}\n`], {
      type: "application/json;charset=utf-8",
    })
  )
  const anchor = document.createElement("a")
  anchor.href = url
  anchor.download = filename
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  URL.revokeObjectURL(url)
}

export function matchesNavHref(
  locationPath: string,
  href: string,
  /**
   * Пути, которые ведут в тот же раздел, но начинаются иначе.
   *
   * Страницы объединились, а адреса редакторов остались прежними: правило
   * маршрутизации по-прежнему лежит в /routing-rules/5/edit, хотя список правил
   * теперь один и живёт в /rules. Без этого списка пункт меню гас, как только
   * человек открывал редактирование.
   */
  aliases: readonly string[] = []
): boolean {
  if (matchesSingleHref(locationPath, href)) return true
  return aliases.some((alias) => matchesSingleHref(locationPath, alias))
}

function matchesSingleHref(locationPath: string, href: string): boolean {
  if (href === "/") {
    return locationPath === "/" || locationPath === ""
  }

  return locationPath === href || locationPath.startsWith(`${href}/`)
}

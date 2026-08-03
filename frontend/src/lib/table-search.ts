/**
 * Поиск по уже загруженной таблице.
 *
 * Серверной пагинации пока нет, поэтому фильтровать нужно то, что и так лежит
 * в памяти. Когда она появится, поменяется источник строк, а этот контракт —
 * «строка ищется по набору своих текстовых полей» — останется.
 */

/** Приводит запрос к виду, по которому сравниваем: без краёв, в нижнем регистре. */
export function normalizeSearchQuery(query: string): string {
  return query.trim().toLocaleLowerCase()
}

/**
 * Каждое слово запроса должно найтись хотя бы в одном поле строки.
 *
 * Слова, а не вся фраза целиком: человек печатает «telegram awg», имея в виду
 * «телеграм, который ходит через AWG», а эти два слова лежат в разных
 * колонках. Поиск подстрокой по склейке полей такой запрос не нашёл бы.
 */
export function matchesSearchQuery(
  fields: Array<string | null | undefined>,
  query: string
): boolean {
  const normalized = normalizeSearchQuery(query)
  if (!normalized) return true

  const haystack = fields
    .filter((field): field is string => Boolean(field))
    .map((field) => field.toLocaleLowerCase())

  return normalized
    .split(/\s+/)
    .every((word) => haystack.some((field) => field.includes(word)))
}

/** Отфильтровать список по запросу, взяв поля через `getFields`. */
export function filterBySearchQuery<T>(
  items: T[],
  query: string,
  getFields: (item: T) => Array<string | null | undefined>
): T[] {
  if (!normalizeSearchQuery(query)) return items
  return items.filter((item) => matchesSearchQuery(getFields(item), query))
}

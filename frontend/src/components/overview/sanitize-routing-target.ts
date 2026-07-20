/**
 * Приводит введённое человеком к имени, которое можно спросить у резолвера.
 *
 * Кириллические домены раньше отвергались: проверка была ASCII-регуляркой, а
 * «сайт.рф» под неё не подходит. Переводить IDN в punycode руками не нужно -
 * это умеет сам разбор URL в браузере, по тем же правилам IDNA, что и
 * адресная строка. Поэтому строка без схемы получает временную `http://`,
 * разбирается, и наружу выходит уже `xn--80aswg.xn--p1ai`.
 */
export function sanitizeRoutingTarget(input: string): string | null {
  const trimmed = input.trim()
  if (!trimmed) {
    return null
  }

  // IPv6 идёт первым: `new URL("http://::1")` не разбирается, а обрамлять
  // адрес скобками ради одной проверки - лишний шаг.
  if (IPV6_PATTERN.test(trimmed)) {
    return trimmed
  }

  // Схему приписываем только если её нет. Иначе «http://» без имени хоста
  // разбирается вторым заходом как «http://http://» и отдаёт хост «http».
  const host = HAS_SCHEME.test(trimmed)
    ? hostnameOf(trimmed)
    : hostnameOf(`http://${trimmed}`)
  if (!host) {
    return null
  }

  // URL отдаёт IPv6 в квадратных скобках; резолверу они не нужны.
  const unwrapped =
    host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host

  if (IPV4_PATTERN.test(unwrapped) || IPV6_PATTERN.test(unwrapped)) {
    return unwrapped
  }

  // После разбора имя уже в punycode, так что ASCII-проверка снова уместна:
  // она отсекает мусор вроде пустых меток и лишних точек.
  return DOMAIN_PATTERN.test(unwrapped) ? unwrapped : null
}

function hostnameOf(value: string): string | null {
  try {
    return new URL(value).hostname || null
  } catch {
    return null
  }
}

const HAS_SCHEME = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//

const DOMAIN_PATTERN =
  /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/

const IPV4_PATTERN =
  /^((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])$/

const IPV6_PATTERN =
  /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4})?:)?((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/

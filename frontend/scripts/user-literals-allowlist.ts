/**
 * Строки, которые проверка `check-user-literals` пропускает.
 *
 * Roadmap: «Не запрещать кириллицу вслепую: законны название языка "Русский",
 * таблица транслитерации, комментарии и тестовые данные.»
 *
 * Здесь два разных списка, и путать их нельзя.
 *
 * `allowedLiterals` — то, что переводить не нужно в принципе: имя продукта,
 * названия протоколов, названия языков, команды оболочки. Такая строка
 * останется здесь навсегда.
 *
 * `untranslatedDebt` — то, что перевести НУЖНО, но ещё не перенесено. Это долг
 * с именами: гейт роняет сборку на любой НОВОЙ строке и требует убрать запись
 * отсюда, как только текст уехал в словари. Список может только уменьшаться.
 */

export const allowedLiterals: readonly string[] = [
  // Названия языков пишутся на самом языке.
  "Русский",
  "English",
  // Имя продукта и его части в шапке и на экране входа.
  "KEEN-PBR",
  "-SB",
  // Название протокола, одинаковое во всех локалях.
  "DNS",
  "nfqws2",
  "KeeneticOS",
  "AmneziaWG",
  "FreeTurn",
  "WDTT",
  "WireGuard",
  // Примеры форматов и технические значения полей. Их перевод сделал бы
  // пример невалидным либо менее узнаваемым.
  "vless1",
  "vless://… vmess://… trojan://… ss://… hy2://… tuic://…",
  "vless://…, trojan://…, hy2://…",
  '{ "type": "ssh", "server": "example.com", "server_port": 22 }',
  "0x00ff0000",
  // Протокольный статус и developer-only invariant errors. Они попадают в
  // диагностику, но не являются самостоятельными пользовательскими текстами.
  "HTTP ${…}",
  "useTheme must be used within a ThemeProvider",
  "useSidebar must be used within a SidebarProvider.",
  "useLanguage must be used within a LanguageProvider",
  // Команды оболочки, которые пользователь копирует как есть. Перевод сломал бы
  // их: это не текст, а ввод для терминала.
  'sh -c "$(curl -fsSL https://raw.githubusercontent.com/blindtechnique/keen-pbr-sb/main/install.sh)"',
  'echo "src/gz nfqws2-keenetic https://nfqws.github.io/nfqws2-keenetic/all" > /opt/etc/opkg/nfqws2-keenetic.conf && opkg update && opkg install nfqws2-keenetic',
]

/**
 * Roadmap: «P1. Убрать пользовательские литералы из frontend вне i18n.
 * Перенести оставшиеся русские подписи, backup-тексты и dependency labels в
 * словари».
 *
 * Ровно эти строки пункт и имеет в виду. Порядок разбора предлагается такой:
 *
 * Список пуст: подписи общих примитивов уехали в `common.chrome.*`, а
 * backup-тексты — в `pages.settings.backup.*` и
 * `pages.settings.softwareUpdate.*`. Пустой список здесь — это не «нечего
 * проверять», а достигнутое состояние: любая новая строка вне словарей роняет
 * гейт, и внести её сюда можно только с причиной.
 */
export const untranslatedDebt: readonly string[] = [
  // Эти сообщения могут дойти до общей обработки ошибок и потому должны быть
  // заменены кодами/ключами i18n. Пока они явно названы здесь, гейт не пропустит
  // новый долг и потребует удалить запись после миграции.
  "Runtime did not become ready: ${…}",
  "routing health endpoint returned an error",
  "transport manager is unavailable",
  "Invalid log response",
  "Invalid log response: lines must be an array of strings",
  "Request timed out after ${…} ms",
  "invalid auth status",
  "transport environment unavailable",
  "Unexpected catalogue preview response",
  "Unexpected catalogue apply response",
]

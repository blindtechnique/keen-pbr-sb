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
  // Схемы ссылок в placeholder поля вставки: это не текст, а образец того,
  // что сюда можно положить. Переводить нечего — схемы одинаковы везде, и
  // переведённая схема была бы ложным примером.
  // Пробелы одинарные: гейт схлопывает их перед сравнением (check-user-literals.ts:111).
  "vless://… vmess://… trojan://… vpn://…",
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
  // Внутренние диагностические причины подготовки и компенсации native-delete.
  // NativeInterfaceDeleteDialog перехватывает их на обеих границах и показывает
  // только локализованные deleteFailed/finishing; `error.message` в UI не уходит.
  "native delete configuration is unavailable",
  "native delete route configuration is unavailable",
  "native delete route restore staging failed",
  "native delete route restore apply failed",
  "native delete tracker restore failed",
  "native delete route staging failed",
  "native delete route apply failed",
  "native delete tracker removal failed",
  // Точные причины остаются в диагностике, но не в основном сообщении UI:
  // log-diagnostics-tools.tsx выводит OperationErrorMessage с переводимым
  // контекстом, а исходный текст — только внутри закрытых «Подробностей».
  "Invalid log response",
  "Invalid log response: lines must be an array of strings",
  // Тайм-аут сохраняется только в скачиваемом JSON диагностики. Его язык и
  // формат не должны менять машинно-читаемый снимок при смене языка панели.
  "Request timed out after ${…} ms",
  // AuthGate.refresh перехватывает эту внутреннюю причину без вывода текста;
  // пользователю показываются существующие локализованные состояния входа.
  "invalid auth status",
  // Query-ошибка не показывается напрямую: TransportUpsertPage использует
  // локализованный loadFailed; TransportsPage не выводит environmentQuery.error.
  "transport environment unavailable",
  // catalog-page.tsx и setup-wizard-page.tsx передают исходную ошибку в
  // OperationErrorMessage: основной текст локализован, причина — в Details.
  "Unexpected catalogue preview response",
  "Unexpected catalogue apply response",
  // lib/runtime-readiness.ts и probes services-status-card.tsx сохраняют
  // исходные причины готовности. Все три обработчика ошибок перезапуска
  // выводят ServiceRestartError → OperationErrorMessage: переводимый итог
  // и закрытые Details, без изменения условий готовности и тайм-аутов.
  "Runtime did not become ready: ${…}",
  "routing health endpoint returned an error",
  "transport manager is unavailable",
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
 * Подписи общих примитивов уехали в `common.chrome.*`, backup-тексты — в
 * `pages.settings.backup.*` и `pages.settings.softwareUpdate.*`.
 * Оставшиеся записи требуют проверки именно основного пользовательского
 * сообщения. Точные технические причины не переводятся задним числом и
 * переходят в allowedLiterals только после проверки всех путей их показа.
 */
export const untranslatedDebt: readonly string[] = []

# Тестовый baseline релиза 12

Локальный baseline обновлён 01.08.2026 для рабочего дерева на базе коммита
`b1d9f651` ветки `feature/upstream-runtime`. На момент проверки ветка была на
14 коммитов впереди опубликованной `origin/alpha`. Локальные изменения ещё не
считаются опубликованной alpha и не прошли установку IPK на роутер.

## Воспроизводимые контракты

- backend API-типы генерируются из `docs/openapi.yaml` закреплёнными
  `js-yaml@5.2.3` и `quicktype@26.0.0`;
- `make generate-check` сравнивает результат с
  `src/api/generated/api_types.hpp`, не изменяя рабочее дерево;
- frontend API генерируется закреплённой в `frontend/package.json` версией
  Orval;
- CI использует Bun 1.3.14 и проверяет `git diff --check`;
- `bun run i18n:check` требует полного совпадения русских и английских
  словарей, проверяет статические ключи и явный список конечных семейств
  динамических ключей;
- тест Keenetic auth не зависит от сетевых интерфейсов или поддержки IPv6 на
  машине сборки. Production по-прежнему получает реальные локальные адреса
  через `getifaddrs()` и сохраняет строгую SSRF-проверку.

## Фактически пройдено локально

| Проверка | Результат |
| --- | --- |
| backend codegen drift | пройдено |
| frontend API regeneration | повторный запуск не создаёт новых изменений |
| i18n parity/usage | 1600 ключей на язык, 1538 статических и 56 разрешённых динамических использований |
| `bun run lint` | пройдено |
| `bun test` | 395 тестов пройдено |
| `bun run typecheck` | пройдено |
| `bun run build` | production bundle собран в Linux-контейнере |
| backend unit и crash smoke | 1431 тест, 12 776 assertions; crash smoke пройден |
| auth без сети и IPv6 | 2 parser-теста, 68 assertions |
| transport-manager `go test ./...` и `go vet ./...` | пройдено |
| IPK validator | 10 тестов пройдено |
| BusyBox package scripts | full/headless postinst, uninstall, dnsmasq helper и netfilter hooks пройдены |
| `git diff --check` | пройдено |

Windows-песочница не даёт Vite обходить некоторые родительские каталоги,
поэтому production build проверен в чистом Linux-контейнере. Это ограничение
локальной среды, а не обход проверки.

## Что ещё отделяет локальный baseline от принятой alpha

1. Собрать aarch64 IPK тем же workflow, которым публикуется alpha.
2. Проверить установку поверх текущей alpha с сохранением конфигурации.
3. Пройти `ALPHA-ROUTER-TEST.ru.md`: LAN и клиенты нативных VPN,
   direct/nfqws2/списочные маршруты, DNS, apply, штатный restart, failover,
   восстановление firewall и WhatsApp/Meta recovery.
4. Подтвердить, что ни один сценарий не требует второго рестарта сервиса или
   повторного обновления страницы.
5. Только после этого считать данный снимок новым alpha baseline и начинать
   следующую крупную backend-функцию.

## CI веток

- `alpha`: полный набор проверок и один экспериментальный aarch64 IPK;
- `next`: тот же набор и aarch64 IPK для следующего этапа приёмки;
- `main`: обычный push пакет не публикует; релизный тег собирает aarch64,
  mips и mipsel.

Продвижение выполняется только в направлении `alpha -> next -> main`.

# Тестовый baseline перед релизом 12

Baseline снят с опубликованной версии `v3.0.7-sb.11`, включая последующие
release-packaging коммиты. Исходный коммит ветки `alpha`:
`5d82bcc5ffbd3f2950ed03e08621198eaa67ec2c`.

## Результаты до изменений релиза 12

| Проверка | Результат |
| --- | --- |
| `bun test` | 38 тестов пройдено |
| `bun run typecheck` | пройдено |
| `bun run build` | production bundle собран |
| `go test ./...` для transport-manager | пройдено |
| `go vet ./...` для transport-manager | пройдено |
| `bun run lint` | известный долг sb.11: 5 ошибок и 3 предупреждения |

Ошибки lint существовали до создания ветки `alpha`: синхронное обновление
локального состояния в эффектах `auth-settings-card`, `logging-settings-card`,
`remote-access-card` и `schedule-picker`, а также смешанный экспорт компонента и
вспомогательной функции в `schedule-picker`. Они не считаются регрессиями
релиза 12, но должны быть устранены до включения lint как обязательного CI gate.

## Обязательный CI baseline веток

- `alpha`: frontend tests, typecheck, production build, Go tests/vet и один
  экспериментальный IPK `aarch64`.
- `next`: тот же набор и один тестовый IPK `aarch64` для установки на роутер.
- `main`: не публикует пакет при обычном push; релизный тег собирает `aarch64`,
  `mips` и `mipsel`.

Переход выполняется только в направлении `alpha → next → main`. Временные
feature-ветки вливаются в `alpha`, а не напрямую в `next` или `main`.

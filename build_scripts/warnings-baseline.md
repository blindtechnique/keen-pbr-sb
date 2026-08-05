# Базовая линия предупреждений

Roadmap: «P0. Добавить политику предупреждений и native sanitizer job. Сначала
включить `-Wall -Wextra` без `-Werror`, зафиксировать baseline и устранить
реальные дефекты.»

**Базовая линия пуста.** Сборка `keen-pbr` с `-Wall -Wextra` на GCC 13.3
даёт ноль предупреждений, и `-DKEEN_PBR_WERROR=ON` проверен: 188 целей,
0 ошибок, 0 предупреждений. Для native CI флаг можно включать.

Ниже — история: что было в первом замере и почему из него что-то подавлено, а
что-то удалено. Она нужна, чтобы подавления не выглядели произволом.

## Как снять заново

```sh
cmake -S . -B build/warnings -G Ninja -DCMAKE_BUILD_TYPE=Release -DWITH_API=ON
ninja -C build/warnings keen-pbr 2>&1 | grep 'warning:'
```

Замер, приведённый ниже, снят на GCC 13.3.0, `-O3`, `WITH_API=ON`,
`USE_KEENETIC_API=OFF`, цель `keen-pbr`, 181 translation unit.

Важно: `-fsyntax-only` для этой задачи не годится. Без оптимизатора не
появляются `-Warray-bounds`, `-Wmaybe-uninitialized` и прочие диагностики,
которые считаются по потоку данных, — измерять надо настоящей сборкой.

## Итого

| Предупреждение | Было | Из `src/` | Состояние |
|---|---:|---:|---|
| `-Warray-bounds=` | 492 | 0 | подавлено для GNU, см. ниже |
| `-Wunused-function` | 7 | 7 | **устранено**, см. ниже |
| `-Wmissing-field-initializers` | 28 | 28 | подавлено, см. ниже |

## Подавлено осознанно

**`-Wmissing-field-initializers`.** В C++ пропущенные члены агрегата
инициализируются значением, а не остаются мусором, поэтому записи вида
`{spec, {}}` в этом коде безопасны и намеренны. Все 28 срабатываний были ровно
такими. Логическое «забыл заполнить поле» ловит clang-analyzer.

**`-Warray-bounds` для GNU.** Ложноположительный класс GCC 12+: анализ границ
проходит сквозь инлайн `nlohmann::json` в libstdc++ и сообщает о выходе за
пределы внутри `_Rb_tree`. Ни одно из 492 срабатываний не указывает на файл из
`src/`; все приходят из third_party и системных заголовков через цепочку
инлайна, поэтому пометка include-каталогов как SYSTEM их не убирает. У Clang
этого класса нет, поэтому подавление ограничено `CMAKE_CXX_COMPILER_ID STREQUAL
"GNU"` — на Clang-сборке (`make clang-check`) предупреждение остаётся включённым.

## Устранено: 7 × `-Wunused-function`

Все семь оказались мёртвым кодом, а не шумом конфигурации, как я предполагал
при первом разборе. Пять — помощники в анонимных пространствах имён, на которые
не осталось ни одной ссылки:

- `src/config/routing_state.cpp` — `detect_ip_family`
- `src/firewall/iptables_verifier.cpp` — `normalize_iptables_port_spec`
- `src/api/server.cpp` — `is_regular_file_or_gzip`
- `src/api/handler_backup.cpp` — `all_groups`

Две — неиспользуемые перегрузки, а не сами функции. Это важно: беглый взгляд по
имени показывал вызовы и создавал впечатление, что код живой.

- `src/health/routing_health_checker.cpp` — `route_type_label(const RouteSpec&)`.
  Вызывается только перегрузка от `DumpedRoute`;
- `src/api/handler_config.cpp` — `restore_exact_config_snapshot` из трёх
  аргументов. Оба вызова идут в четырёхаргументную версию с callback.

Одна — тестовый вход:

- `src/api/handler_backup.cpp` — `validate_confined_restore_target`, вызывается
  только из `validate_confined_restore_target_for_test`. Определение закрыто тем
  же `#ifdef KEEN_PBR3_TESTING`, что и вызов; удалять нельзя, тест реальный.

Полный набор тестов после удаления: 1616/1616, 14 708 assertions.

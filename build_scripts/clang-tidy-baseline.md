# Базовая линия clang-tidy

Roadmap: «P1. Подключить уже настроенный `clang-tidy` без замедления каждого
alpha build. Зафиксировать версию и baseline только для project-owned C++,
сначала запускать curated checks на изменённых файлах либо отдельным nightly
job, а полный скан сделать блокирующим лишь после устранения подтверждённых
дефектов и стабилизации времени.»

Снят весь `src`. Блокирующим полный скан не делается: пункт велит сначала
разобрать находки.

`make clang-tidy-curated` покрывает восемь каталогов, где ошибка дороже всего, —
это то, что имеет смысл гонять на изменённых файлах. Числа ниже приведены и по
ним, и по всему `src`.

## Что и чем снято

Clang 18.1.3, конфигурация `.clang-tidy` из корня репозитория
(`clang-analyzer-*`, `bugprone-*` с тремя исключениями), compile database из
Clang-сборки `WITH_API=ON USE_KEENETIC_API=ON BUILD_TESTS=ON`.

Охват — **186 translation units проекта**: сначала 47 из каталогов, где ошибка
дороже всего (`src/runtime`, `src/firewall`, `src/routing`, `src/lists`,
`src/dns`, `src/backup`, `src/connections`, `src/config`), затем оставшиеся 139.

Предупреждения из `third_party` в счёт не идут: их 22, все из `cpptrace`, и это
чужой код. Если в снимок попали `bugprone-unhandled-self-assignment`,
`bugprone-macro-parentheses` и подобные — смотрите путь, они оттуда.

На двух ядрах весь прогон занял около двух часов.

```sh
make clang-tidy-curated                       # восемь самых дорогих каталогов
# весь src целиком — тем же clang-tidy по compile database:
#   clang-tidy -p build/cmake-clang-tidy <файлы из src/**/*.cpp>
```

## Итого: 155 предупреждений в 49 файлах

| Проверка | Всего | Из них в curated-восьмёрке |
|---|---:|---:|
| `bugprone-empty-catch` | 78 | 16 |
| `bugprone-implicit-widening-of-multiplication-result` | 47 | 10 |
| `bugprone-unchecked-optional-access` | 19 | 10 |
| `bugprone-optional-value-conversion` | 2 | 1 |
| `bugprone-unused-return-value` | 1 | 0 |
| `bugprone-narrowing-conversions` | 1 | 0 |
| `bugprone-branch-clone` | 1 | 1 |

Где плотнее всего:

| Файл | Штук |
|---|---:|
| `src/daemon/daemon_core.cpp` | 20 |
| `src/daemon/daemon_runtime.cpp` | 16 |
| `src/backup/restore_journal.cpp` | 14 |
| `src/api/handler_nfqws.cpp` | 11 |
| `src/util/last_command_failure.cpp` | 7 |
| `src/update/maintenance_lock.cpp` | 6 |
| `src/daemon/daemon_resolver.cpp` | 6 |
| `src/firewall/iptables.cpp` | 5 |

## Что стоит разобрать первым

**`bugprone-unchecked-optional-access` (19).** Самая дорогая категория:
разыменование пустого `std::optional` — это падение демона на роутере.

Две площадки я посмотрел вручную, и обе выглядят ложными, но по разным причинам:

- `src/routing/route_table.cpp:190` —
  `it == end() || !it->retry_after.has_value() || now_() >= *it->retry_after`.
  Короткое замыкание гарантирует проверку до разыменования;
- `src/dns/dnsmasq_gen.cpp:52,55` — тернарник вида
  `registry.keenetic_snapshot() ? registry.keenetic_snapshot()->field : {}`.
  Здесь замечание менее пустое, чем кажется: проверяется результат **первого**
  вызова, а разыменовывается результат **второго**. Пока метод возвращает одно
  и то же, всё верно; если он когда-нибудь станет обновлять кэш или окажется
  под конкурентным доступом, между двумя вызовами появится окно. Дешевле
  сохранить результат в локальную переменную, чем доказывать инвариант.

Остальные семнадцать площадок не смотрел — каждая требует решения владельца
кода, а не гейта. Из новых стоит отметить `ndms_interface_inventory.cpp:381,386,388`
(три подряд в одном месте) и `daemon_core.cpp:1117`.

**`bugprone-empty-catch` (78).** Плотнее всего: `daemon_core.cpp` — 18,
`daemon_runtime.cpp` — 13, `restore_journal.cpp` — 14, `daemon_resolver.cpp` — 6.
Проглоченное исключение в коде восстановления — это как раз то место, где
молчаливый отказ дороже всего. Возможно, там намеренный best-effort cleanup; но
тогда это стоит написать в самом `catch`, а не оставлять пустым.

**`bugprone-implicit-widening-of-multiplication-result` (47).** Умножение в
`unsigned int` с последующим расширением до `size_t`. На 64-битном aarch64
переполнение маловероятно, но эти выражения — размеры буферов, и лучше считать
их сразу в `size_t`.

**`bugprone-unused-return-value` (1)**, `src/http/http_transport.cpp:116`:
отброшено возвращаемое значение `unique_ptr::release()`. Здесь это **не** утечка:
`curl_slist_append` возвращает голову той же цепочки, `release()` отдаёт
владение, `reset(appended)` его забирает. Идиома верная, проверка её не
распознаёт — но записать стоит, чтобы никто не «чинил» её вслепую.

**`bugprone-optional-value-conversion` (2)**,
`src/firewall/nftables_verifier.cpp:462`: `optional<unsigned char>` →
`unsigned char` → обратно в `optional`. Механически исправимо.

**`bugprone-branch-clone` (1)** — две ветки с одинаковым телом. Либо
сокращается, либо одна из них должна была делать другое.

## Чего этот снимок не говорит

Он не говорит, какие из 155 находок — настоящие дефекты. Две проверенные
вручную площадки `unchecked-optional-access` оказались: одна ложной, одна
заслуживающей правки; единственная `unused-return-value` — ложной. То есть
доля шума заметная, и разбирать нужно по одной.

Предположение, которое я сделал в прошлый раз, подтвердилось: в `src/daemon`
находок больше всего — 42 в трёх файлах. Это тот самый класс, который пункт
roadmap про разделение `Daemon` и должен разгрести.

# Сопровождение форка keen-pbr-sb

## Обновление из оригинального keen-pbr

Рекомендуемая схема remotes:

```sh
git remote add origin https://github.com/blindtechnique/keen-pbr-sb.git
git remote set-url --push upstream DISABLED
git fetch origin
git fetch upstream
```

`upstream` должен указывать на `maksimkurb/keen-pbr`, а `origin` — на форк.
Обновление лучше выполнять в отдельной ветке:

```sh
git switch -c sync/upstream-YYYY-MM-DD
git merge upstream/main
```

После разрешения конфликтов обязательны:

```sh
make transport-manager-test
make frontend-build
make test
```

Transport manager намеренно находится в `extensions/transport-manager`, а
интеграция с ядром ограничена API-прокси, OpenAPI-схемой, упаковкой и страницей
React. Поэтому обычные изменения upstream чаще всего переносятся без сложного
переписывания. Наибольшая вероятность конфликтов — в `docs/openapi.yaml`,
сгенерированных API-типах, маршрутах frontend и Keenetic Makefile.

Оценка трудоёмкости одного обновления:

- изменения без пересечения с интеграцией: примерно 1–3 часа вместе с тестами;
- изменения OpenAPI/frontend/пакетной системы: от половины до двух рабочих дней;
- крупная переработка модели outbounds или API: оценивается отдельно.

## Архитектуры Keenetic / NetCraze

GitHub Actions уже умеет собирать полный Keenetic-релиз для:

- `aarch64-3.10`;
- `armv7-3.2`;
- `mips-3.4`;
- `mipsel-3.4`;
- `x64-3.2`.

Go transport-manager собирается статически для `arm64`, `armv7`, `mips`,
`mipsle` и `amd64`. C++-часть собирается в соответствующих Entware builder
контейнерах. То есть сама компиляция других архитектур уже автоматизирована и
не требует отдельной разработки.

Основная стоимость — аппаратная проверка: запуск сервиса, TUN, iptables/ipset,
DNS Override и реальный трафик нужно проверять хотя бы на одном устройстве
каждого семейства. Пока нет тестовых роутеров, разумно публиковать aarch64 как
проверенную архитектуру, а остальные пакеты помечать как экспериментальные.

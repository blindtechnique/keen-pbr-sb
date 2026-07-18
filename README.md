# keen-pbr-sb

Русскоязычный форк [maksimkurb/keen-pbr](https://github.com/maksimkurb/keen-pbr) для маршрутизаторов Keenetic/Netcraze с Entware и управляемыми интерфейсами sing-box.

Проект остаётся полностью открытым: исходный код форка, transport-manager, установщик и веб-интерфейс находятся в этом репозитории. Каталог `third_party` содержит только открытые зависимости с их лицензиями. Локальные каталоги `.cache`, `build` и `frontend/node_modules` не являются частью репозитория и не должны загружаться на GitHub.

> Это независимый проект, не связанный с Keenetic или Netcraze и не поддерживаемый ими официально.

## Отличия от оригинального keen-pbr

- отдельный transport-manager для создания и контроля sing-box TUN;
- импорт `vless://`, `vmess://`, `trojan://`, `ss://`, `hysteria2://`, `hy2://`, `tuic://`, `anytls://`, `socks://`, `http://` и `https://`;
- произвольный sing-box outbound в формате JSON, поэтому работа не ограничена VLESS/Reality;
- поиск существующего sing-box в стандартных каталогах и возможность выбрать свой путь;
- установка и обновление официального sing-box из интерактивного установщика;
- нативные интерфейсы Keenetic, WireGuard и AmneziaWG в общей схеме outbounds;
- создание привязанного outbound и групп `urltest` для failover;
- sing-box TUN со стеком gVisor и `auto_route: false`: таблицами маршрутизации владеет keen-pbr;
- автоматические правила FORWARD для управляемых TUN;
- настраиваемые bootstrap DNS для разрешения имени VPN-сервера до запуска туннеля;
- URL-списки в текстовом формате и бинарные наборы sing-box `.srs`;
- DNS Override для Keenetic, генерация dnsmasq-конфигурации и DNS-диагностика;
- страница «Соединения»: активные TCP/UDP-соединения, состояния, адреса, порты, маршрут, фильтр, автообновление и история до двух часов в оперативной памяти;
- диагностический отчёт из веб-интерфейса;
- интерактивные установщик и деинсталлятор.

## Поддерживаемые платформы

Основная протестированная цель — Keenetic с Entware `aarch64`. Сборка также предусмотрена для `armv7`, `mips`, `mipsel` и `x64`, но каждую модель и ABI желательно проверять отдельно. Прошивка должна поддерживать Entware, policy routing и netfilter.

## Установка одной командой

Сначала установите Entware в `/opt`, затем подключитесь к роутеру по SSH как `root`:

```sh
sh -c "$(curl -fsSL https://raw.githubusercontent.com/blindtechnique/keen-pbr-sb/main/install.sh)"
```

Если нет `curl`:

```sh
sh -c "$(wget -qO- https://raw.githubusercontent.com/blindtechnique/keen-pbr-sb/main/install.sh)"
```

Установщик определяет архитектуру Entware, загружает подходящий `.ipk` из последнего GitHub Release, проверяет `SHA256SUMS`, предлагает установить или выбрать sing-box и настроить Keenetic DNS Override. Повторный запуск этой же команды выполняет обновление с сохранением конфигурации.

Важно: одного исходного кода в ветке `main` недостаточно. В GitHub Release должны находиться собранные пакеты с именами вида:

```text
keen-pbr_<версия>_keenetic_<abi>_aarch64.ipk
SHA256SUMS
```

## Удаление

```sh
sh -c "$(curl -fsSL https://raw.githubusercontent.com/blindtechnique/keen-pbr-sb/main/uninstall.sh)"
```

Деинсталлятор отдельно спрашивает об удалении конфигурации, sing-box, установленного этим проектом, и DNS Override. Entware и внешняя установка sing-box не удаляются.

## Быстрый старт

1. В разделе «Транспорты» добавьте нативный интерфейс или sing-box-подключение.
2. Для sing-box можно вставить share-link либо готовый outbound JSON.
3. При необходимости задайте bootstrap DNS IP-адресами, по одному в строке.
4. Запустите транспорт и создайте outbound для появившегося интерфейса.
5. Выберите outbound в правиле маршрутизации или DNS.
6. Для резервирования создайте `urltest` из двух или более outbounds.

Доменные списки работают, когда клиент получает DNS через dnsmasq роутера. DoH/Secure DNS или запущенный на клиенте VPN могут обойти правила роутера.

### Бинарные списки SRS

В поле URL списка можно указать прямую ссылку на `.srs`, например:

```text
https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ai-!cn.srs
```

keen-pbr скачивает набор и вызывает `sing-box rule-set decompile`. Поддерживаются точные домены, суффиксы доменов и IP CIDR. Regex, keyword, source CIDR и инвертированные правила нельзя без потерь представить в dnsmasq/ipset, поэтому они пропускаются; для SRS требуется sing-box 1.10 или новее.

## Сборка и публикация

Инструкции по первой публикации находятся в [docs/PUBLISH_GITHUB.ru.md](docs/PUBLISH_GITHUB.ru.md), по синхронизации с оригинальным проектом — в [docs/FORK_MAINTENANCE.ru.md](docs/FORK_MAINTENANCE.ru.md).

```sh
make test
make package-keenetic-all
```

Не добавляйте в Git `.cache`, `build`, `frontend/node_modules` и готовые архивы. Пакеты `.ipk` публикуются как assets отдельного GitHub Release.

## Лицензия и обратная связь

Лицензия — [LICENSE](LICENSE). Ошибки и предложения: [GitHub Issues](https://github.com/blindtechnique/keen-pbr-sb/issues).

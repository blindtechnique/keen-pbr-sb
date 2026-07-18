# MyKeenPBR transport manager

Локальный companion для Keenetic создаёт и контролирует transport-интерфейсы, а
`keen-pbr` остаётся владельцем policy routing, списков и failover.

## Возможности

- нативные интерфейсы Keenetic и AmneziaWG без вмешательства в их lifecycle;
- изолированный TUN sing-box с `auto_route: false` и без DNS hijack;
- импорт подключений по ссылкам `vless://`, `vmess://`, `trojan://`, `ss://`,
  `hysteria2://`/`hy2://`, `tuic://`, `anytls://`, `socks://`, `http://` и
  `https://`;
- готовый sing-box outbound JSON для любого другого поддерживаемого протокола;
- локальный API `127.0.0.1:12122` с Bearer-аутентификацией;
- CRUD конфигурации, запуск, остановка, статус и автоматическое восстановление
  с exponential backoff;
- атомарная запись конфигурации и права `0600` для конфигов и логов;
- проверка сгенерированного конфига через `sing-box check` до запуска;
- совместимость со старым типом `sing-box-vless-reality`.

Ссылки и outbound JSON содержат секреты, поэтому API списка конфигураций их не
возвращает. Пустое поле при редактировании сохраняет уже записанное подключение.

## Поиск sing-box

Сначала используется `sing_box_binary` из конфига. Если файл отсутствует,
manager автоматически ищет:

1. `/opt/bin/sing-box`;
2. `/opt/sbin/sing-box`;
3. `/opt/usr/bin/sing-box`;
4. `/opt/etc/awg-manager/singbox/sing-box`.

Таким образом, можно использовать sing-box, уже установленный AWG Manager.

## Сборка

Нужен Go 1.22 или новее:

```sh
go test ./...
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -trimpath -buildvcs=false -ldflags='-s -w' \
  -o transport-manager-aarch64 ./cmd/transport-manager
```

Из корня форка бинарники для всех поддерживаемых архитектур собираются командой
`make transport-manager-build`.

## API

```sh
curl http://127.0.0.1:12122/healthz
curl -H 'Authorization: Bearer YOUR_KEY' http://127.0.0.1:12122/v1/transports
curl -X POST -H 'Authorization: Bearer YOUR_KEY' \
  http://127.0.0.1:12122/v1/transports/proxy/up
```

## Граница ответственности

Transport manager не меняет `ip rule`, таблицы policy routing и правила
маркировки keen-pbr. Для каждого управляемого TUN он добавляет в конец цепочки
`FORWARD` по одному разрешающему правилу через совместимый `iptables`/`ip6tables`
frontend. Правило помечается комментарием, если ядро это поддерживает; дубли и
правила, оставшиеся после аварийного завершения, удаляются при следующем старте.
Тогда же завершаются только те осиротевшие процессы sing-box, чья команда
ссылается на конфиг настроенного транспорта в runtime-каталоге keen-pbr.

Каждый sing-box transport автоматически получает стабильную отдельную `/30`
из пула `172.19.0.0/16`; поле `tun_address` позволяет переопределить её вручную.
Менеджер сверяет здоровье интерфейса с уже выполненными urltest-проверками
keen-pbr и после трёх отрицательных вердиктов перезапускает зомби-транспорт.

Адрес прокси-сервера нельзя направлять в этот же прокси. API показывает сервер
без реквизитов подключения, а Web UI предлагает создать первым правило `ignore`
и список `transport_servers` одной кнопкой.

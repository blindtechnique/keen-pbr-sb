# Журнал изменений keen-pbr-sb

Здесь перечислены изменения именно форка `keen-pbr-sb`. История оригинального keen-pbr остаётся в upstream-репозитории [maksimkurb/keen-pbr](https://github.com/maksimkurb/keen-pbr).

Формат основан на Keep a Changelog. Установленные сборки обозначаются как `3.3.0-ГГГГММДДччммсс`: первая часть — базовая версия keen-pbr, последние 14 цифр — время сборки форка в UTC.

## [3.3.0] — в разработке

Ниже собраны все изменения после последнего редактирования этого файла 17 августа 2026 года, включая синхронизацию с новой базой upstream и последующие исправления на реальном Keenetic.

### Добавлено

- Импорт штатных WireGuard и AmneziaWG из URI и файлов `.conf` прямо в KeeneticOS. Поддерживаются актуальные AmneziaWG 2.0 и legacy-конфигурации 1.0–1.5; секретный текст передаётся один раз и не сохраняется в журнале панели.
- Автоматическое включение импортированного интерфейса, сохранение конфигурации KeeneticOS и создание связанного маршрута keen-pbr. После неоднозначного ответа панель сама сверяет результат и завершает настройку появившегося интерфейса без повторной отправки секрета.
- Управление импортированными WG/AWG в общем списке «VPN, прокси, группы»: пользовательский псевдоним и страна, редактирование обычным карандашом и удаление обычной корзиной. Техническое имя интерфейса остаётся только в подробностях.
- Включение, выключение и перезапуск существующих клиентских WireGuard/AmneziaWG прямо из обычного переключателя и кнопки перезапуска в списке.
- Удаление принадлежащего панели штатного туннеля вместе со связанным маршрутом, сохранением KeeneticOS и возможностью безопасно закончить прерванную операцию. Удалённый слот можно освободить для последующего импорта после явного отказа от сохранённой копии отката.
- Инвентарь штатных интерфейсов KeeneticOS с различением принадлежащих панели, чужих, удалённых и требующих завершения операций записей. Внешние ответы не содержат внутренних transaction ID, маркеров и имён файлов снимков.
- Единая карточка проверки сайта на дашборде: доступность из браузера и с роутера, фактический маршрут/туннель, покрытие nfqws2 и проверка по реестру. Проверка реестра расположена непосредственно под адресом сайта.
- Установка закреплённой версии sing-box из панели с предварительной оценкой возможности, прогрессом загрузки, отменой, проверкой результата и сохранением заменённого бинарника для отката.
- Проверка фактического внешнего адреса и страны каждого транспорта, а также ручная проверка задержки штатных VPN-интерфейсов.
- Полное OpenAPI-описание API панели, включая аутентификацию, резервные копии, диагностику, обновления, транспортные операции и закрытые ручные native-мутации.
- Встроенный каталог вместо обязательного скачивания при первой установке, миграция источников с недоступного `repo.hoaxisr.ru` на SagerNet и возможность планировать отдельный список как всегда прямой.
- Настраиваемая ёмкость ipset для больших списков и долговечное, атомарно сохраняемое согласие на проверку сайта по реестру.
- Транзакционный lifecycle nfqws2 хранит точные пакеты до и после мутации,
  однозначно завершает прерванную операцию при следующем запуске и позволяет
  установить отсутствующий компонент прямо с его страницы. Пользовательская
  конфигурация не заменяется без заранее сохранённой точной копии.
- Локальный gate `make check-ndmc-env` воспроизводимо проверяет, что системный
  `ndmc` запускается без несовместимого Entware `LD_LIBRARY_PATH`.

### Изменено

- Фоновое завершение удаления native VPN больше не отменяется обновлениями
  статуса и задержки: после одного нажатия на корзину внутренняя запись отката
  удаляется без отдельного пользовательского сценария.
- Проект перешёл на базовую версию **3.3.0**; версия пакета и шапка панели используют `3.3.0` и дату/время конкретной сборки вместо старой метки `sb.12`.
- Изменения upstream перенесены в форк без дублирования его механизмов: обновлены каталог, API, жизненный цикл sing-box, конфигурационные проверки и инфраструктура сборки.
- Технические метки импорта вида `kpbr-ni-v1-*` больше не выдаются пользователю как названия. Для интерфейса используется заданный псевдоним; домен или IP предлагается только как редактируемый вариант псевдонима.
- Проверка сайта показывает nfqws2, реестр и доступность до блока маршрутизации, чтобы результат читался сверху вниз как один ответ, а не как набор разрозненных инструментов.
- Управляющий сокет демона изолирован от тяжёлых операций, а API не собирает дорогие снимки состояния, когда ими никто не пользуется.
- Журнал браузера для native-операций получил межвкладочную блокировку и автоматическое согласование результата, но восстановление больше не требует от обычного пользователя отдельной скрытой кнопки.
- Проверки каталога, обновлений и привилегированных loopback-запросов ограничены по объёму и времени; редиректы для привилегированных запросов запрещены.
- IPv4/IPv6 firewall использует общий RAW PREROUTING-контур, а обычный runtime
  refresh переиспользует подтверждённые live sets, когда поколение содержимого
  не изменилось. Полное стриминговое применение остаётся проверяемым fallback.
- Единственный ответ на вопрос, активна ли маршрутизация, теперь принадлежит
  `RuntimeStateStore`; отдельное изменяемое поле `Daemon` удалено, а API/SSE
  строят проекцию из того же состояния.
- `ConfigStore` публикует конфигурацию и соответствующие ей outbound marks как
  одно неизменяемое поколение. Длительные читатели закрепляют shared snapshot и
  не смешивают данные двух последовательных apply.
- API-операции runtime и SIGHUP rollback удерживают точное активное поколение
  конфигурации до завершения, а отложенный list/firewall staging использует
  закреплённый снимок кэша без ссылки на изменяемого владельца `CacheManager`.
- Сохранение активной конфигурации передаёт уже выданный exact mutation lease
  в типизированный `config_preapply` lifecycle единственного firewall-owner.
  Проверка и при необходимости восстановление owned SNAT текущего поколения
  выполняются вне control loop; кандидат применяется только продолжением того
  же terminal после `FinalizationProof`. Preapply не обновляет remote lists,
  resolver, маршруты или Meta-состояние, имеет конечный hot-retry и сохраняет
  точный остаток conntrack cleanup без повторного удаления уже обработанных
  marks. Чистый отказ до handoff возвращает тот же lease и закрывает WAL как
  неизменённый runtime; неоднозначный или уже committed terminal сохраняет
  recovery evidence без нового пользовательского сценария восстановления.
- При активном runtime production config-save теперь проводит `config_preapply`,
  candidate и при необходимости rollback в контуре единственного
  `RuntimeFirewallOperationOwner`, не освобождая и не получая заново тот же
  физический mutation lease. До первой мутации закрепляются exact committed
  resolver/list snapshot базового поколения; candidate использует собственные
  pinned list/resolver inputs и точный route checkpoint. Candidate `G -> G+1`
  остаётся приватным до подтверждённых route/firewall и resolver stream, после
  чего `ConfigStore` CAS и один небросающий checkpoint публикуют согласованные
  config, outbound marks, реализованный firewall core, resolver cursor и runtime
  generation. Typed rollback имеет terminal identity `G+1 -> G+2`, возвращает
  опубликованный runtime к базовому `G` и после вошедшего COMMIT использует
  сохранённый realized candidate core как firewall preimage; базовый preimage
  допустим только при доказанном отсутствии candidate-мутации, а неоднозначный
  исход fail closed. Candidate и подтверждённый rollback по одному разу
  выполняют соответствующие Meta, native-VPN и stale-flow tails. Пришедшие во
  время операции SNAT/catalog изменения не переигрывают старый candidate:
  после возврата lease запускается свежий NAT/full backend resnapshot. Точный
  файловый rollback теперь сам закрывает WAL; ошибка удаления или fsync active
  marker переводит операцию в `UNKNOWN`/`recovery_required`, не выдавая ложный
  rollback-success. Для Entware/Keenetic GCC 8 old ABI точная публикация
  Config использует доказуемый no-throw relocation-swap через move construction
  вместо недоказуемого для старого `std::string` aggregate swap.
- Внутренние изменения runtime/firewall из восстановления правил, URLTest,
  Keenetic DNS, отложенного старта и автообновления списков проходят через
  единого владельца мутации. Занятый владелец сохраняет один ограниченный
  поколением отложенный запрос без расходования бюджета повторов; принудительное
  применение обновлённого списка не теряется при совпадении с read-only/304.
- Для следующего этапа выноса firewall I/O подготовлены неизменяемая
  backend-транзакция и один фазовый retry-handoff. Транзакция различает вход в
  commit и его возврат, проверяет Meta UDP/443 перед первоначальным и резервным
  commit и допускает только один переход `RulesOnly` -> `PreserveSets`.
  Отдельные snapshot-контракты выводят из закреплённых config/marks точную
  generation-fenced authority для последующей owned conntrack-очистки.
  Retry-coordinator сохраняет один claim через timer, worker и control,
  аутентифицирует terminal callback и не теряет более новую recovery revision
  либо один coalesced trailing run. Точное наблюдение native-VPN передаётся
  одним неизменяемым generation-fenced снимком интерфейсов и сервисов; только
  типизированная операция может принять его, а отмена, stale generation и
  отказ scheduler/queue имеют однозначного владельца результата.
- Для off-loop apply добавлен долговечный worker-envelope без второй
  state machine. Неподделываемый running claim, один mutation lease и
  caller-owned terminal mailbox переживают копирование или отмену задачи,
  отказ очереди, исключение worker и уничтожение операции до постановки в
  очередь. Результат либо точное требование переснять входы публикуется один
  раз до best-effort уведомления control loop.
- Локальный B1-контур добавляет долговечного control-владельца
  terminal outcome. Владелец сам выполняет и без второго fallible-шва сохраняет
  переходы `worker_running -> control_pending -> complete`, удерживает result,
  mutation lease и одноразовый noexcept-checkpoint публикации, а exact
  coordinator completion имеет приоритет над пришедшим раньше lease-free
  `lost_claim`. Тесты контракта покрывают обе очередности этой гонки, повтор
  после исключения и явный drain уже работающего terminal при shutdown.
- Отдельный worker-attempt выполняет одной попыткой SNAT-observation,
  stage/Meta-preflight/commit и post-COMMIT проверки Meta/FastNAT, сохраняя
  неоднозначный commit без автоматического повтора. Точный authority-снимок
  owned conntrack marks теперь захватывается до COMMIT и переносится в result:
  finalizer не должен строить ему замену после изменения firewall generation.
  Production-сигнатура native VPN уже передаёт интерфейсное и сервисное
  наблюдения одним immutable generation-fenced объектом; exact TCP cleanup
  остаётся dormant, пока retry-coordinator владеет firewall backend.
- Первый production-срез B1 локально подключает отложенные firewall
  `schedule/defer` к типизированному exact catalog/claim/terminal API и отдельной
  ограниченной очереди `1x1`. Один Daemon-owned active context удерживает
  immutable worker input, точную SNAT-recovery authority, mutation lease и
  одноразовый terminal owner; scheduler/queue rejection, отмена, stale claim и
  worker outcome завершаются через тот же durable drain. Best-effort wake
  подкреплён watchdog, а shutdown закрывает admission, отменяет timer/queued
  work, прокачивает terminal до и во время quiesce, затем останавливает worker и
  выполняет финальный drain. Control publication использует безаллокаторные
  swap-checkpoints и освобождает lease только после coordinator completion.
  Неоднозначный entered COMMIT не получает автоматического replay даже при уже
  накопленном trailing intent: продолжение возможно только через новый полный
  backend resnapshot. Exact native-direct source cleanup выполняется worker-side
  лишь после доказанного commit и не повторяется в control tail.
- Асинхронный transport/ownership-контур этого B1-среза вынесен из `Daemon` в
  отдельный `RuntimeFirewallOperationOwner` без обратного указателя на `Daemon`.
  Он единолично удерживает active context, typed schedule/defer, очередь `1x1`,
  terminal wake/drain, повторяющийся watchdog, shutdown fence и долговечный
  pending successor. Точный SNAT recovery и самый новый совместимый prepared
  catalog сохраняются до доказанного приёма successor новым context/coordinator;
  более новое catalog-less поколение не наследует устаревший catalog. Отказ
  control-post, регистрации watchdog, выделения нового context либо timer arm
  не теряет terminal outcome и не оставляет mutation lease без владельца.
- Это извлечение ownership, а не завершение firewall P1 и не полное разделение
  `Daemon`: построение worker input, static-route reconciliation, публикация
  rules/LKG/resolver/Meta/conntrack и политика ambiguous COMMIT пока остаются в
  daemon-specific domain state и control-tail callback. Актуальный production
  target слинкован полностью (253/253); отдельная owner/terminal/worker цель
  прошла 26/26 сценариев и 509/509 assertions, итоговое независимое review не
  нашло P0/P1-блокеров.
- Следующий локальный срез **B1-immediate** убирает старый синхронный первичный
  runtime refresh: attempt 0 без фиктивного таймера сразу передаётся тому же
  `RuntimeFirewallOperationOwner` и `RuntimeFirewallRetryCoordinator`.
  Move-only completion intent завершает periodic URLTEST, owned-SNAT repair и
  FULL netfilter probe только после точного terminal outcome; queue/scheduler
  rejection, stale claim и shutdown не оставляют operation без владельца.
  Backend failure attempt 0 переходит к attempt 1 через одну секунду, а
  исчерпавшийся SNAT pre-worker retry уходит в тихое обслуживание через 60
  секунд без same-attempt loop. Старый compatibility-путь удалён, число прямых
  production-вызовов `apply_firewall()` уменьшено с 12 до 11. Узкий suite
  прошёл 43/43 сценария и 666/666 assertions; blockers-only review дал
  P0/P1 = 0.
- Для следующего route-среза построение желаемого поколения выделено в чистые
  `PlannedRoutingState`/`plan_routing_state()`: planner принимает immutable
  reachability snapshot, не выполняет Netlink I/O и не изменяет входные данные.
  Совместимый `populate_routing_state()` сохраняет прежние callback caching и
  порядок route/rule mutation, cleanup и adoption. Routing suite прошёл 66/66
  сценариев и 261/261 assertions, включая parity, deterministic replay,
  nested URLTEST и IPv6-off; независимое review дало GO без P0/P1.
- Вторая половина R0 переносит блокирующее IPv6-наблюдение, снимки main routes
  и интерфейсов и построение желаемого route/rule generation первичной runtime
  attempt в тот же owned worker. Immutable `RuntimeRouteHealthPlan` несёт
  serial, runtime generation и route epoch; одноразовый typed checkpoint
  допускает firewall backend только после подтверждённой публикации того же
  поколения. Stale, route-unavailable, mutation failure и shutdown не запускают firewall.
  Watchdog повторно поднимает отпущенный control claim, shutdown будит worker,
  а main-table `RTM_NEWROUTE`/`RTM_DELROUTE` инвалидируют план и сохраняют один
  coalesced refresh даже после уже выданного ack. Ожидание checkpoint не держит
  affinity/backend lock. Kernel route/rule mutation пока остаётся короткой
  control-loop фазой до R1. Focused gates: route preparation 3/3 (32
  assertions), route health 5/5 (65), InterfaceMonitor 4/4 (31), отдельный
  owner suite 45/45 (675); blockers-only review дал GO без P0/P1.
- Первый prerequisite-срез R1 выделяет постоянного
  `RuntimeRoutingOperationOwner`, который единолично хранит mutable-ledger
  `RouteTable` и `PolicyRuleManager`. Запрос связан точным tuple operation,
  runtime generation, intent, inventory revision и route epoch; stale/replay
  отклоняются до Netlink. Читатели получают только неизменяемую копию с
  монотонной ревизией, а частичная ошибка сохраняет lifetime-owned typed
  journal и рабочий снимок для следующего exact resnapshot. Результат намеренно
  называется `compatibility_converged`, а не commit. Production/test targets собраны; узкий набор прошёл
  6/6 сценариев и 65/65 assertions, независимый blockers-only review дал GO,
  P0/P1 = 0.
- Второй prerequisite-срез R1b добавляет одну совмещённую route/rule
  транзакцию с заранее опубликованным lifetime-owned журналом, точными
  per-object receipts, immutable fence и commit-before-cleanup. Нормальная
  очистка policy rules использует только явный owner-ledger; kernel-shape
  heuristic разрешён лишь отдельному recovery-проходу. Foreign/unrepresentable
  route/rule, wildcard rule identity, неоднозначный kernel slot, неканонический
  default-route запрос и racer во время rollback/cleanup дают отказ или
  `cleanup_pending`, но не широкое удаление. Production backend намеренно
  fail-closed: до появления единого exclusive-writer lease, полного raw
  inventory и честных conditional replace/delete capability-preflight
  останавливает операцию до первого Netlink-вызова, поэтому R1b ещё не включён
  в `Daemon` и не объявлен production commit-authority. Оба target слинкованы;
  focused suite прошёл 40/40 сценариев и 340/340 assertions, полный gate —
  3266/3266 и 35 748/35 748; независимый blockers-only review дал GO без P0/P1.
- Следующий wiring-срез подключает `RuntimeRoutingOperationOwner` к `Daemon`:
  отдельные mutable `route_table_` и `policy_rules_` удалены, initial setup,
  reconcile, lifecycle/rollback cleanup, interface wake и runtime-снимки идут
  через одного владельца. Вложенные manager-деструкторы для него разоружены,
  поэтому teardown выполняется один раз под тем же owner; обычные standalone и
  dry-run manager сохраняют прежний cleanup. Завершённый inventory публикуется
  атомарным immutable `shared_ptr`, поэтому status/SSE не ждут worker-held
  routing mutex. Interface wake при занятом owner сохраняется в
  дедуплицирующем pending-наборе и также не блокирует control loop.
- В основном runtime refresh совместимый route/rule reconcile теперь
  выполняется в worker до firewall backend. Fence поколения и route epoch
  повторяется уже после захвата combined owner. Успешный immutable snapshot
  строится из фактических manager-ledger после reconcile, поэтому неудавшееся
  удаление obsolete route/rule больше не скрывается желаемым планом. До первого
  Netlink write заранее выделяется консервативная публикация с явным
  `inventory_complete=false`: даже если точную post-operation копию нельзя
  выделить, уже применённое kernel-поколение не превращается в ложный mutation
  failure, а снимок не выдаётся за полный. Неизвестный эффект удаления rule
  теперь оставляет logical/owned ledger и защищает route-anchor той же таблицы;
  shutdown/rollback соблюдают тот же порядок. Отдельный
  `compatibility_cleanup_pending` не называется convergence. Признаки точности
  ledger и известности kernel-эффектов проходят в runtime-state: health отвечает
  unknown вместо ложного mismatch, а worker выдаёт `stale` и не допускает
  firewall до свежего авторитетного reconcile. Покрыты статические тестовые
  сценарии отказа до/после delete-effect, allocation-fallback, pre-mutation
  dump/fence failure и разных route/rule backend-объектов. Дополнительное
  fail-closed усиление сохраняет route-anchor при tracked-unowned, foreign и
  restart-orphan policy rule, отличает нормальное desired rule той же таблицы
  от чужой зависимости и не принимает ошибку orphan dump за пустой inventory.
  Неоднозначный rollback одной dual-stack family и неудавшееся восстановление
  replaced route заранее получают консервативную запись owner-ledger. Повторный
  startup использует live-aware repair. Exact identity публикует consumed
  high-water marks даже при ошибке до первой записи, но journal и fallback
  выделяются до consume, поэтому ранняя allocation failure оставляет identity
  повторяемым.
- Единый `RuntimeRoutingInventoryAuthority` теперь используется worker и всеми
  синхронными firewall apply. Incomplete/unknown routing и известный
  live-missing desired route не допускают backend COMMIT; health/API сразу
  получают false-маркеры при сохранённом firewall LKG. Interface-probe больше
  не открывает параллельный routing writer, а ставит coalesced central refresh.
  Route-preparation после выполненной route mutation переносится allocation-free
  через placement-new move-конструкцию, поэтому старый ABI GCC 8.4 не зависит
  от небезопасного предположения о `noexcept std::string::swap`, а ошибка строки
  не превращается в ложный ambiguous firewall COMMIT.
  После освобождения owner control loop только повторно сверяет
  exact context, публикует metadata и выдаёт ack;
  netlink mutation там больше нет. Это всё ещё compatibility
  offload, а не включение exact R1b: изменение epoch/внешний writer во время
  legacy netlink-фазы остаётся причиной немедленного coalesced retry, пока raw
  inventory/owned-preimage backend не завершён. Прежний production gate на
  Entware/Keenetic GCC 8.4 прошёл 281/281 build-шагов. Замороженный production-
  снимок прошёл host gate: preflight 18/18, monolithic 3295/3295 и 36 063
  assertions, 12 narrow-целей 756/756 и 14 374 assertions, crash smoke и
  production link/version; суммарно 4051 doctest-сценарий и 50 437 assertions
  без ошибок. Текущий post-snapshot batch 26 августа отдельно прошёл общий
  compile-only target-gate реальным GCC 8.4 с `BUILD_TESTS=ON`: завершён граф
  из 739 compile/link шагов и слинкованы ARM64 `keen-pbr`, monolithic
  `keen-pbr-tests`, `keen-pbr-runtime-firewall-owner-tests` и
  `keen-pbr-runtime-firewall-lifecycle-completion-tests`. Все четыре ELF имеют
  interpreter `/opt/lib/ld-linux-aarch64.so.1`; без QEMU они не исполнялись.
  IPK и роутер не менялись.
- Эти новые локальные срезы ещё **не закрывают firewall P0-1/P1/B1**: первичный
  backend apply, блокирующие route/link observation/planning и совместимый
  kernel route/rule reconcile первичной runtime attempt уже вынесены из
  control loop, но exact raw backend, daemon-specific publication tail,
  прямые cleanup/backend writers и синхронные apply-группы остаются. Все sync apply теперь
  fail-closed проверяют authoritative routing, но сами ещё выполняются в
  control loop. После проверенного safety-снимка отдельный startup-срез передал
  его legacy recursive firewall retry тому же
  `RuntimeFirewallOperationOwner` и уменьшил прямые вызовы с 11 до 10.
  Следующий локальный P0-1 restart-срез подключил эти prerequisites к
  production API: request guard передаёт точный уже выданный mutation lease
  без release/reacquire, HTTP worker ждёт exact-once
  `RuntimeFirewallLifecycleTerminal`, а control loop только принимает операцию
  в owner и не блокируется ожиданием worker. Один retained lease и тот же
  lifecycle source проходят queue/pre-worker failure, bounded successor и
  shutdown drain; rejection возвращает исходный lease, final terminal
  различает verified success, shutdown, not-verified и ambiguous COMMIT.
  Restart использует `RouteReconcileMode::Strict`, сохраняющий действующее
  поколение `FirewallApplyMode::PreserveSets` и обязательную проверку resolver
  reload/stream. Уже совершённый firewall COMMIT без подтверждённого resolver
  не считается успешным restart и не вызывает replay исходной мутации. Старый
  прямой синхронный `restart_routing_runtime()` удалён, поэтому число прямых
  production-вызовов `apply_firewall()` уменьшилось с 10 до 9.
  Следующий локальный START-срез передаёт уже выданный lease тому же owner и
  удаляет прямой синхронный `start_routing_runtime()`. Cache-only DNS остаётся
  до первой мутации; routes/firewall/owned conntrack выполняются worker-side,
  resolver `activate` — отдельным stream-worker с exact attempt-id/epoch.
  Кандидат не публикуется до подтверждения resolver; bounded transient retries
  равны 100/200/400 мс. Любой окончательный отказ, потерянный resolver control
  handoff либо ошибка обязательной runtime-публикации удерживает тот же
  terminal/lease до off-loop rollback routes, firewall и resolver. Поэтому
  на этом checkpoint прямых `apply_firewall()` оставалось восемь в пяти
  функциональных группах: cold startup, Keenetic DNS candidate/rollback,
  pre-apply SNAT repair, URLTEST candidate/rollback и общий synchronous
  config wrapper. Текущий owner-switch убрал из последней группы активный API
  config-save; stopped-runtime save, SIGHUP и list-refresh пока используют
  прежнюю обёртку, поэтому сами legacy call sites ещё не удалены.
  В том же несобранном batch устранены terminal/liveness-разрывы: firmware
  netfilter refresh не отменяет foreground lifecycle timer; trailing source
  после verified START/restart отделяется в background successor; последняя
  route-epoch fence не позволяет объявить START успешным по устаревшему route
  plan: позднее изменение топологии расходует конечный START-бюджет
  100/200/400 мс и после него запускает rollback вместо бесконечного
  same-attempt defer. Четыре последовательных scheduler/executor rejection до
  `begin_worker()` завершаются не внутри transport-owner, а типизированным
  terminal Daemon; START выполняет обычный off-loop rollback, после чего lease
  освобождается до `not_verified`. Coordinator и queue mailbox получили
  небросающие ownership-locks, поэтому pre-worker transfer не зависит от
  ошибки platform mutex, а stale claim не создаёт второго владельца. Поздний
  SNAT/catalog delta после сохранения completion переносится в successor; при
  исчерпании transport-бюджета restart exact payload отделяется в один
  background resnapshot, а foreground lease освобождается перед
  `not_verified`. START имеет отдельный конечный бюджет из четырёх отказов
  передачи rollback worker и после его исчерпания завершает fail-closed
  finalizer вместо зависания в `starting`. Сбой сохранения необязательного
  background tail не меняет уже подтверждённый foreground result. Promoted
  watchdog делает не более одного launch за tick. Shutdown переводит
  foreground timer в typed terminal, а timer-id observation failure идёт через
  exact rejection terminal вместо ложного `consumed`.
  Обязательные resolver `activate` для START и `reload` для foreground restart
  теперь используют общий асинхронный `ResolverStreamCoordinator`: hook и
  15-секундное ожидание exact dnsmasq stream не блокируют control loop, terminal
  паркуется до fenced completion, а потерянный control wake подбирается
  watchdog. Restart без необходимости DNS refresh больше не получает ложный
  resolver failure; неуспешный reload передаётся существующему background retry
  без повторного firewall apply. Production hook не может зависнуть навсегда:
  общий KeeneticOS `safe_exec` ограничивает его 30 секундами, завершает process
  group с 2-секундным grace и затем `SIGKILL`; после успешного hook отдельно
  действует 15-секундный stream timeout.
  START resolver generation также строится по точному подготовленному
  native-VPN DNS access policy этой же lifecycle-операции, а не по ещё старому
  глобальному inventory до публикации кандидата. Тот же список участвует в
  вычислении expected hash и затем передаётся dnsmasq; отдельная регрессия
  закрепляет приоритет подготовленного кандидата над stale fallback.
  Финальный объединённый gate обоих lifecycle wiring-срезов прошёл: monolithic
  `3341/3341` и `36 767/36 767`, owner `75/75` и `1251/1251`, lifecycle
  completion `4/4` и `28/28`, все обязательные native/rescue/DNS/router-info/
  resolver/journal/lock narrow-цели и crash smoke. Реальный Entware/Keenetic
  GCC 8.4 собрал 285 target-объектов; IPK прошёл identity validator и
  изолированный install/reinstall/remove/recovery lifecycle. На том checkpoint
  P0-1 оставался открытым для пяти sync apply-групп, exact raw routing backend
  и дальнейшего
  извлечения daemon-specific publication tail. Следующий pre-generation SNAT
  barrier нельзя делегировать простым ранним исключением: API и SIGHUP приняли
  бы его за изменившийся runtime и запустили ложный rollback. Для этого среза
  требуется typed pre-apply-deferred continuation с тем же exact mutation
  lease, без ручного пользовательского повтора.
  Установленный Keenetic IPK `3.3.0-20260826231313`
  (`05997c8f81ff-dirty`, SHA-256
  `b56f111d2447a0db28a1da176776b446f9fb101e841127f2462478b4a581bb1f`)
  прошёл router acceptance. Первая candidate-попытка была корректно откатана:
  `status` через 6 секунд увидел штатное незавершённое initial URLTest
  поколение. Исправленный установочный gate дождался строгого `Overall: OK`
  под PENDING/update-lock, выдержал ещё 30 секунд и завершился `DEPLOY-OK`.
  Независимый postflight подтвердил точную binary identity, живые S79/S80,
  routing `Overall: OK`, свободную update-lock, неизменные SHA конфигурации и
  rescue `ready=true`, `rollback_available=true`, `pending=false`,
  `unknown=false`; прежний IPK `3.3.0-20260825071624` сохранён как rollback
  previous с SHA-256
  `e95b8085586f7c72724e429cb2c80fb7ad041e7dafd898edfbc1a6b54f4b95b4`.
- Для следующего pre-generation SNAT-среза подготовлен типизированный
  `config_preapply` foundation без включения незавершённого пути в production.
  Worker различает обязательный exact cleanup remainder и полный снимок,
  разрешённый только после собственного наблюдения missing SNAT; healthy,
  unknown, malformed generation/mask/IPv6 scope, неподдерживаемый cleanup mode
  и неоднозначный COMMIT не получают расширенной destructive authority.
  `RuntimeFirewallOperationOwner` переносит тот же move-only mutation lease и
  одноразовый `noexcept` continuation через bounded retry/defer и возвращает их
  только после типизированного `TerminalOwner::FinalizationProof`; обычный
  shutdown возвращает точный token, а деструктор не вызывает внешний callback.
  API guard умеет один раз принять обратно тот же физический lease и проверяет
  одновременно token и принадлежность исходному `RuntimeMutationAdmission`,
  поэтому foreign lease с совпавшим номером отклоняется. Узкий owner/terminal
  suite прошёл 80/80 сценариев и 1382/1382 assertions; затронутые production и
  test-объекты собраны реальным Entware/Keenetic GCC 8.4, итоговое независимое
  review не нашло оставшихся P0/P1. Старый синхронный barrier пока сохранён;
  полный suite, IPK и роутер этим foundation-срезом не запускались.
- Production config-save теперь передаёт уже выданный точный
  `RuntimeMutationAdmission::Lease` в адаптер демона и обязательно возвращает
  его в тот же API guard до интерпретации результата, rollback либо WAL commit.
  Адаптер пока вызывает прежний синхронный apply, поэтому этот срез не выдаётся
  за off-loop переключение. Короткий lease-bound handoff gate закрывает окно
  второго writer только на время текущего запроса: после exact return он
  снимается немедленно, а при нарушении внутреннего контракта — после
  emergency quiesce и фиксации recovery WAL при unwind запроса. Постоянного
  `shutdown`/poison, отдельного пользовательского восстановления и ручного
  повтора этот контракт не добавляет; неполная production-связка отклоняется
  до prepare, записи файлов и открытия WAL. Узкий gate прошёл 9/9 admission
  сценариев и 71/71 assertions; реальный Entware/Keenetic GCC 8.4 собрал шесть
  затронутых объектов с API и три без API. Независимое blockers-only review
  дало GO без P0/P1; полный suite, IPK и роутер не запускались.
- Router-info обновляется single-flight без RCI I/O под cache mutex. Принятый
  снимок живёт 30 секунд, конкурентные читатели получают stale LKG, а полный
  RCI failure повторяется не чаще раза в 30 секунд и не затирает LKG.
- После выхода URLTest child его принадлежащие потоки очищаются по умолчанию;
  временный отказ cleanup получает ограниченную повторную попытку.

### Исправлено

- Колокольчик больше не показывает десятки одинаковых записей о кратких сбоях
  Meta/WhatsApp UDP/443 и PPE de-offload: внутри одного процесса сохраняется
  только самый новый инцидент каждого вида, а записи предыдущего процесса
  снимаются лишь после найденного в том же журнале запуска совпадающих
  build/commit. Состояние текущего процесса не объявляется исправленным без
  доказательства; сравнение по порядку строк не зависит от часового пояса или
  коррекции часов роутера.
- Управляющие вызовы `iptables` и `ip6tables` теперь ограниченно ждут общий
  xtables lock, учитывая оба реально встречающихся диалекта: современный
  `-w <секунды>` и KeeneticOS `iptables 1.4.21` с одним `-w`. Capability
  определяется отдельно для IPv4/IPv6 и не кэшируется по временному Busy.
  Внешний deadline остаётся обязательным; если завершение probe или самой
  команды нельзя доказать, фактическая операция не повторяется, а частичный
  вывод очищается до всех parser'ов и не может ложно доказать отсутствие
  цепочки. Живая read-only проверка подтвердила bare `-w` на установленном
  Keenetic; изменённые production/test-объекты собраны GCC 8.4, без IPK и
  установки на роутер.
- Панель стратегий nfqws больше не назначает первую стратегию каталога, когда
  backend честно сообщает, что активный `nfqws2.conf` не совпал ни с одной из
  них. Разбор показывается только для применённой или явно открытой стратегии,
  заголовок называет просматриваемый разбор, а не состояние системы. Кнопка
  «Сохранить» не создаёт byte-identical override встроенного профиля и не
  замораживает автоматическую подстановку WAN; «Применить» недоступна для ещё
  не сохранённого нового черновика. Четыре фронтенд-коммита Claude интегрированы
  с сохранением исходной истории.
- Английская backend-причина `disabled by configuration` в русской карточке
  диагностики теперь отображается как «Отключено в настройках»; неизвестные
  диагностические подробности сохраняются без подмены. Ошибка сохранения
  привязки уже созданного native VPN также локализована и явно запрещает
  повторный импорт; восемь внутренних delete-диагностик, которые никогда не
  выводятся пользователю, документированы в allowlist.
- Версия установленной сборки теперь имеет единый вид
  `v3.3.0-ГГГГММДДччммсс` в daemon API, шапке, package control и frontend
  marker. Строгий IPK-validator сверяет timestamp, binary identity, активный
  JavaScript и реально отдаваемые gzip-копии `index.html`/JS; старый `sb.12`,
  stale entrypoint и несовпадающие package/frontend данные отклоняются. Source
  identity учитывает untracked-файлы, которые упаковщик копирует в build tree,
  поэтому пакет больше не может выглядеть собранным из clean commit при наличии
  неопубликованного исходника.
- Текущий предсборочный gate после этих изменений прошёл: frontend `904/904`
  (2633 assertions), identity/IPK-validator `29/29`, monolithic C++
  `3342/3342` (36 773 assertions), а также все обязательные native, rescue,
  DNS, resolver, lock и runtime-firewall standalone-наборы. Новый IPK после
  этого объединённого checkpoint на момент записи ещё не собирался.
- Восстановление встроенной стратегии nfqws больше не записывает tombstone,
  который сразу снова скрывал её после reload. Для неактивной стратегии
  заголовок разбора берётся из builtin-каталога. Изменение перенесено из
  Claude-коммита `4a7212e3` локальным интеграционным коммитом `05997c8f`;
  добавлены пять backend-регрессий, frontend и transport-manager gates прошли.
- Завершение `RuntimeFirewallOperationOwner` больше не оставляет mutation lease
  во внешне удержанном context и не вызывает внешний terminal callback после
  разрушения owner. После остановки worker/timer очищаются lease, operation,
  terminal owner и callbacks, а lifecycle source переводится в однозначный
  `not_verified`; owner-suite закрепляет отсутствие callback re-entry и
  исправляет точную START/restart failure injection.
- В новом lifecycle completion удалено повторное неверное предположение о
  `noexcept std::string::swap` на Entware GCC 8.4. Заранее подготовленный
  terminal теперь публикуется placement-new move-конструкцией; после входа в
  `settle()` нет строкового allocation/swap-шва.
- Для GCC 8.4 со старым ABI libstdc++ устранено неверное предположение, что
  move-assignment результата со `std::string` всегда `noexcept`. Точный
  worker-result теперь конструируется через заранее выделенный holder и
  `optional::emplace`, а потенциально бросающее сохранение terminal detail
  выполняется до checkpoint `prepared`; после entered COMMIT не добавлен новый
  fallible publication seam и неоднозначная операция не переигрывается.
- Ранний отказ неавторизованного native/API-запроса теперь всегда получает
  `Cache-Control: no-store` ещё до чтения тела. Удаление native VPN и очистка
  tombstone явно проверяются с обычной действующей сессией без повторного ввода
  пароля; устаревшие ожидания step-up удалены из интеграционных тестов.
- Обязательный `make test` больше не пропускает отдельный
  `keen-pbr-native-direct-observation-tests`. Инъекция смены типа интерфейса в
  cooperative-delete тесте теперь действует в обеих областях точного guard и
  не зависит от исторического номера чтения каталога.
- Обязательный gate теперь включает отдельные
  `keen-pbr-runtime-firewall-owner-tests` и
  `keen-pbr-runtime-firewall-lifecycle-completion-tests`; статическая сверка
  Makefile/CMake прошла 4/4. Assertions над `shared_ptr` в owner-тесте явно
  приводятся к `bool`, поэтому doctest 2.5.1 больше не пытается форматировать
  сам указатель и не останавливает host-компиляцию.
- После удаления native WG/AWG вместе с интерфейсом и маршрутом удаляется его
  локальная карточка псевдонима/страны. Осиротевшие карточки больше не создают
  отдельную вкладку KeeneticOS с уже отсутствующими `WireguardN`.
- Удаление импортированного WG/AWG с пользовательским псевдонимом больше не
  блокируется как `snapshot_unreadable`: зашифрованный снимок восстанавливает
  исходную каноническую подпись вместе с псевдонимом.
- Фоновая финализация удаления корректно учитывает различие runtime-каталога и
  running-config KeeneticOS. Другие существующие WG/AWG больше не блокируют
  удаление локального снимка и tombstone уже исчезнувшего интерфейса.
- Импорт WG/AWG больше не останавливается на валидном Keenetic running-config, не зависает в `executor_blocked` после фактически созданного интерфейса и корректно принимает интерфейс, который появился после неоднозначного ответа.
- После успешного или восстановленного импорта конфигурация KeeneticOS включается и сохраняется, конфигурация keen-pbr обновляется, а новый маршрут появляется без ручного обновления страницы.
- Завершение native-импорта больше не теряет введённые псевдоним, выбор
  связанного маршрута и разрешённое автоопределение страны, если ответ Keenetic
  пришёл после закрытия модального окна или обновления этой вкладки. Сохраняется
  только несекретный план оформления; URI и ключи в него не попадают. Ответ
  восстановления `no_work` теперь сначала сопоставляется с уже созданным
  интерфейсом по принятому псевдониму, а не стирает план маршрута и страны.
- Псевдоним импортируемого WG/AWG теперь передаётся в фактически используемое
  KeeneticOS имя импортируемого файла, а не только в игнорируемый прошивкой
  комментарий `# Name`. После подтверждённого импорта описание интерфейса в
  самом Keenetic становится ровно выбранным человеком именем; служебная метка
  переносится в невидимое поле peer и больше не добавляется к названию. Обычные
  редактирование, восстановление и удаление через корзину при этом сохраняются.
- Для native WG/AWG результат разрешённого автоопределения страны сохраняется в
  карточке после создания и используется как флаг даже при отсутствии серверного
  адреса в несекретном native-tracker. Для ранее добавленного native-туннеля
  режим «Автоматически» определяет страну по адресу, фактически видимому через
  его точный интерфейс.
- Импортированный интерфейс можно переименовать, указать ему страну, редактировать тем же карандашом и удалять той же корзиной, что и остальные записи. Флаг выбранной страны теперь показывается непосредственно в строке native-интерфейса.
- Разбор `.conf` принимает legacy-параметры AmneziaWG 1.0–1.5 и корректно различает допустимые необязательные значения вместо общей ошибки «параметр имеет недопустимое значение».
- Удаление сначала применяет удаление связанного маршрута, а при известном отказе Keenetic восстанавливает его. Отсутствующий диагностический снимок зависимостей без единой найденной ссылки больше не блокирует навсегда удаление принадлежащего панели туннеля; реально найденные ссылки по-прежнему показываются и блокируют операцию.
- Корзина native VPN стала единственным пользовательским действием удаления: один клик запускает удаление самого VPN и связанного маршрута без второго диалога, ввода имени, галочек, отдельного восстановления и повторного пароля в уже авторизованной сессии.
- Если Keenetic уже удалил native-интерфейс, панель автоматически завершает и удаляет служебную запись, сбрасывает кэш и убирает исчезнувшую строку. Служебные записи отката и их проверки больше не показываются пользователю отдельным разделом и не запускают скрытую повторную авторизацию при открытии страницы.
- Удаление отключённого WG/AWG теперь завершается и тогда, когда исчезнувший интерфейс уже нельзя найти в списке устройств Linux: панель восстанавливает штатное имя `nwgN`, автоматически удаляет служебный снимок завершённого удаления и сразу освобождает импорт из файла или URI.
- Исправлены ложные «результат импорта неизвестен», бесконечные межвкладочные блокировки, подмена семейства восстановления и утечка внутренних идентификаторов через подпись интерфейса.
- Проверка доступности сайта больше не полагается только на один HTTP-ответ роутера и различает доступный пользовательский путь, маршрут через туннель и обработку nfqws2.
- Восстановлено плавное перемещение индикатора вкладок в стиле KeeneticOS: глобальная настройка сокращения движения больше не превращает его в мгновенный прыжок, а само подчёркивание перемещается композитной анимацией и не срывается при изменении раскладки страницы.
- Усилена аутентификация после смены пароля роутера; устаревшие сессии не продолжают работать, а растяжение ключа ограничено на уровне всего роутера.
- Обновление sing-box не перезаписывает чужой или недоступный для проверки бинарник, корректно отменяется и не оставляет ложного доступного отката.
- Исправлены мобильная компоновка строк и обычная корзина удаления native WG/AWG, кнопки обновлений и проверки, сообщения уведомлений и привязка результата проверки транспорта к точному интерфейсу. Из раскрытой строки убраны внутренние диагностические пояснения о готовности управления; неизвестная роль больше не отключает управление клиентским WG/AWG.
- После передачи WG/AWG в Keenetic окно добавления больше не считается формой с
  несохранёнными изменениями; быстрое автоматическое завершение закрывает его
  после создания карточки и маршрута. Из превью удалено внутреннее пояснение о
  локальном структурном разборе, не помогающее пользователю выполнить импорт.
- Если Keenetic принял одноразовый WG/AWG import и потребовал фоновое завершение,
  окно один раз показывает состояние завершения и автоматически закрывается без
  вопроса о несохранённых изменениях. Привязка маршрута, применение конфигурации
  и автоопределение страны продолжаются на странице списка и больше не ждут
  ручного закрытия модального окна.
- После автоматического закрытия окна импорта в правом нижнем углу показывается
  короткий индикатор «VPN импортируется». Он сменяется подтверждением и исчезает
  только после создания записи, привязки маршрута и завершившегося перезапуска
  transport-manager.
- После распознавания native URI поле с секретной ссылкой блокируется, а фокус
  переходит к безопасному превью. Попытка продолжить без имени возвращает фокус
  к полю псевдонима и заметно выделяет предложенный вариант. Пока импорт и
  привязка маршрута не завершены, нельзя открыть ещё одну форму добавления, а
  импортированный интерфейс не показывается как внешний туннель KeeneticOS.
- `RulesOnly` refresh сохраняет точные static generations предыдущего apply и
  не сообщает designed self-heal внешнего dispatcher как системную аварию.
- nfqws2/package mutation больше не теряет собственный журнал при boot recovery,
  не запускает maintainer scripts вне владельца транзакции, не зависит от
  порядка старта Entware SSH listener и пишет шаги в журнал именно той
  транзакции, где они произошли. Обновление и packet capture не требуют
  повторного пароля в уже авторизованной сессии.
- Frontend API client повторно сгенерирован из текущей OpenAPI-схемы, поэтому
  модели панели и backend-контракт снова совпадают byte-for-byte по генератору.

## [3.1.1-sb.12] — подготовительный журнал до перехода на 3.3.0

### Добавлено

- Мастер первого запуска проводит через создание связки «туннель + маршрут» одной транзакцией, выбор сервисов из каталога и проверяемое применение результата. Можно использовать уже существующий маршрут; промежуточный черновик и повторная отправка всей конфигурации не создаются.
- Снимок последней неудачной привилегированной команды в диагностике. Запись ограничена по размеру, атомарна, очищена от секретов и некорректного UTF-8 и не создаёт отдельного постоянно опрашиваемого API.
- Интеграционные сценарии восстановления firewall после частично удалённых или повреждённых цепочек, повторного применения конфигурации и сохранения чужих правил и битов меток.
- Опциональный экспериментальный режим `daemon.meta_udp443_policy: messages_first` отклоняет только UDP/443 к адресам штатного IP-компаньона Meta/WhatsApp с меткой его маршрута. Клиент может перейти на TCP, что иногда ускоряет первую доставку, но живой тест Android также показал последующее зависание сессии WhatsApp без отправки сообщения. Поэтому рекомендуемым остаётся `balanced`; интерфейс прямо предлагает вернуться к нему при сообщениях без галочек. Режим не блокирует UDP/3478, UDP/5349 и P2P-медиа на высоких портах; предупреждение также описывает влияние на Instagram и другие сервисы Meta, возможную дополнительную задержку звука звонка на 10–20 секунд и необходимость отключённой IPv6-маршрутизации до появления проверенного IPv6-покрытия. Owned-правило проверяется и удаляется также после аварийного завершения демона и при удалении пакета.

### Изменено

- Новая установка sing-box зафиксирована на уже установленной и проверенной версии `1.13.14`: установщик больше не запрашивает и не предлагает непроверенный последний выпуск. Уже выбранный локальный бинарь не заменяется автоматически.
- Бэкенд маршрутизации синхронизирован с архитектурными изменениями keen-pbr 3.1.1: состояние iptables применяется через две сменяемые генерации, а стабильные dispatcher-цепочки переключаются только после успешной подготовки и проверки новой конфигурации.
- Содержимое ipset читается через строгий XML-разбор с ограничением объёма до изменения рабочего состояния. Сети `/0` безопасно разворачиваются в две половины адресного пространства.
- Правила `multiport` автоматически делятся с учётом лимита xtables в 15 слотов. Имена интерфейсов проходят единую строгую проверку до формирования команд firewall.
- Интерфейс списков, DNS, резервных копий, настроек, маршрутов и туннелей стал компактнее: связанные настройки собраны вместе, таблицы используют единые строки и действия, а в формах и группах приоритетны понятные пользователю имена вместо технических идентификаторов.
- Конфигурации sing-box в общем и изолированном режимах явно задают DNS-resolver для доменных адресов и совместимы с требованиями sing-box 1.12 без включения устаревшего режима.

### Исправлено

- Для штатного списка IP-адресов WhatsApp зависшее соединение подтверждается отдельной одноразовой проверкой через одну секунду. Остальные списки сохраняют общий осторожный интервал, а действующий звонок, ответивший поток и чужие биты метки по-прежнему защищены от очистки.
- Восстановление отсутствующих dispatcher-цепочек и builtin-hook больше не требует полного удаления управляемого firewall-состояния и не затрагивает чужие цепочки.
- Повреждение только одной A/B-генерации теперь исправляется из подтверждённой рабочей генерации; если достоверного состояния нет, применение завершается безопасно до изменения ipset.
- Очистка NAT не выполняется раньше проверки, что целевая генерация действительно неактивна.
- Диагностический снимок не перезаписывается подавленными probe-командами и корректно обрабатывает таймаут, сигнал, ошибку `fork`/`pipe` и ненулевой код завершения.
- Маршруты и policy rules с протоколом владения keen-pbr сходятся после исчезновения или конкурирующей замены: сервис заменяет только собственное конфликтующее состояние, сохраняет чужие записи и откатывает незавершённое изменение.
- `ndmc` и системные сценарии Keenetic запускаются без унаследованного Entware `LD_LIBRARY_PATH`, поэтому системная утилита больше не подхватывает несовместимую `libc`; диагностический вывод при этом сохраняется.
- Транспорт считается исправным только после свежей успешной проверки, результат которой можно однозначно связать с его интерфейсом. Отсутствующий, устаревший или неатрибутируемый результат больше не даёт ложный зелёный статус.

## [3.0.7-sb.11] — 2026-07-22

### Добавлено

- **Резервное копирование и восстановление.** В настройках можно собрать выборочную копию общих настроек, транспортов, исходящих соединений, DNS, списков, правил и nfqws2. Перед обновлением и восстановлением создаётся rollback-копия, которую можно скачать на компьютер.
- **Анализ зависимостей до удаления.** У списков и исходящих соединений заранее показано, какие правила, DNS-серверы и группы от них зависят; связанные объекты открываются по ссылке.
- **Имена интерфейсов из NDMS.** На дашборде используется имя, заданное в прошивке, в настройках показываются пользовательское и техническое имена, а в соединениях системное имя перенесено в подсказку.
- **Расширенная информация о транспортах.** В карточке видны протокол, защита, SNI, сетевой транспорт и страна сервера. Страну можно выбрать вручную, определить через внешний сервис с месячным кэшем или не показывать вовсе.
- Выключатели sing-box и nfqws2 в карточке служб и ручная проверка задержки для нативных и управляемых туннелей.
- **Защищённый внешний доступ к панели.** Порт открывается только по явному выбору пользователя и при включённой авторизации; разрешённый доступ не создаёт ложное системное предупреждение.
- Импорт и экспорт исходящих соединений, транспортов и файлов nfqws2. Полный экспорт транспортов выполняется отдельным авторизованным запросом и содержит необходимые для восстановления секреты с явным предупреждением перед скачиванием.
- Безопасное обновление nfqws2: изменённый пакетный `nfqws2.conf` сохраняется как стратегия `default (ГГГГ.ММ.ДД)`, а изменение только `IPV6_ENABLED=0` не создаёт лишнюю копию. Встроенные стратегии автоматически получают активные WAN-интерфейсы.

### Изменено

- Интерфейс переработан в знакомой для пользователей KeeneticOS/NDMS логике: единая типографика и синяя палитра, компактные формы и карточки, светлая и тёмная темы, фиксированные панели действий и новый логотип. В пакет включены только необходимые кириллические и латинские WOFF2-наборы Roboto.
- Мобильные списки и правила получили отдельную компактную компоновку, работающий выбор нескольких строк и перетаскивание на pointer-событиях. Массовые действия перенесены в непрозрачную нижнюю панель, а мобильная шапка остаётся закреплённой.
- Раздел последовательно переименован из «Интерфейсов» и «Точек выхода» в **«Исходящие соединения»**. Пользовательское слово `outbound` убрано из форм и подсказок; технические теги и формат конфигурации не изменились. nfqws2 перенесён рядом с транспортами.
- Карточки транспортов и дашборд стали компактнее и показывают полезное состояние: активный маршрут, резерв, протокол, задержку и зависимости вместо внутренних PID и повторяющихся технических статусов.
- Kill-switch в форме исходящего соединения получил понятное описание каждого режима, а выбор интерфейса — метку протокола (`AWG/WG`, VLESS, OpenVPN, IKEv2 и другие).
- Проверка соединений и транспорта использует общий кратко кэшируемый снимок здоровья. FORWARD-правила проверяются раз в 30 секунд, conntrack разбирается не чаще раза в две секунды, имена устройств кэшируются на минуту, история ограничена 1500 соединениями, а невидимые строки таблицы не отрисовываются.
- HTTP-запросы, внешние команды и их вывод получили ограничения времени и объёма. Статические файлы отдаются потоково, версионированные ассеты кэшируются браузером.
- Сохранение конфигурации и восстановление резервной копии выполняются транзакционно с атомарной записью и возвратом предыдущего runtime-состояния при ошибке.

### Исправлено

- Проверка маршрута принимает кириллические домены и URL: имя переводится в punycode штатным браузерным разбором.
- Кратковременное расхождение во время замены маршрутов больше не вызывает ложное `unexpected route present in table`: ошибка подтверждается повторным снимком через 200 мс.
- PID-файл обновления проверяется через `kill(0)` и `/proc/<pid>/cmdline`; устаревший файл удаляется. Прогресс обновления читается из локального атомарного состояния без повторного обращения к GitHub каждые три секунды.
- Выключенный пользователем IPv6 больше не создаёт предупреждение. Разбор `iptables-restore` понимает сообщение `line N failed` без двоеточия и показывает проблемное правило.
- Пустой ответ NDMS об именах интерфейсов теперь кэшируется, а неожиданный тип полей `connected` и `link` не роняет весь запрос.
- Ссылка TUIC без учётных данных больше не приводит к ошибке разбора.
- Статус исходящего соединения не помечается ошибочным «транспорт не отвечает», если фактический ping через него успешен.
- Бинарные `.lua.gz` в резервной копии кодируются в Base64 и не вызывают `invalid UTF-8 byte`. Ограничены размер, количество и пути файлов; при ошибке восстановления nfqws2 выполняется автоматический rollback.
- Исправлены выбор правил на телефоне, расписание cron, прокрутка редакторов nfqws2 и каталога, а также удаление списка из правила с другими оставшимися условиями.
- Кнопки проверки обновлений keen-pbr-sb и nfqws2 всегда сообщают результат, в том числе когда новых версий нет.
- Флаг страны формируется из ISO-кода в браузере, а ручной ввод заменён локализованным списком стран с теми же эмодзи.
- Экспорт транспортов больше не теряет share-link, outbound JSON, UUID и остальные параметры подключения. Повседневный endpoint остаётся обезличенным; секреты возвращает только отдельный авторизованный экспорт.

## [3.0.7-sb.10] — 2026-07-20

### Исправлено

- **Резервные DNS-серверы не перетаскивались.** Строка получала вид «места, откуда её забрали», уже в момент нажатия на ручку, а этот вид прячет её содержимое. Указатель оказывался над невидимым элементом раньше, чем браузер успевал начать перетаскивание, и жест отменялся, не начавшись. Нажатие теперь только разрешает строке двигаться, а серую пунктирную заготовку она принимает, когда перетаскивание действительно началось.

### Изменено

- Доступ к панели снаружи убран из интерфейса: на части прошивок правило межсетевого экрана не переживало перенастройку сети, а полурабочая точка входа в панель управления — не то, что стоит показывать. Вернётся, когда будет надёжно работать.
- README короче: раздел разработки и инструкция сопровождения форка убраны.

## [3.0.7-sb.9] — 2026-07-20

### Исправлено

- **Обновление из веб-интерфейса оставляло dnsmasq на старой конфигурации, и доменная маршрутизация переставала работать.** Помощник перезапускал dnsmasq через init-скрипт и считал успехом сам факт вызова. На Keenetic PID-файл регулярно расходится с реальным процессом: остановка сообщала `failed`, запуск — `already running`, dnsmasq продолжал работать со старым `conf-script`, а вместе с ним пропадали и директивы ipset, и TXT-запись с хешем. Внешне это выглядело как вечный баннер «требуется перезапуск», и лечилось только перезагрузкой роутера. Теперь процесс ищется по имени, а не по PID-файлу, остановка ждёт завершения и при необходимости применяет KILL, устаревший PID-файл удаляется, а результат перезапуска проверяется. Само обновление дополнительно переподключает конфигурацию и пишет в журнал, удалось ли это.

### Добавлено

- **Раздел каталога в интерфейсе** — 87 заготовок по категориям, с поиском, отметкой уже добавленных и выбором, куда направлять их трафик. Отдельно выбирается интерфейс, через который скачивается сам каталог: он лежит на GitHub, то есть ровно там, куда многие и не могут дотянуться напрямую. Выбранный маршрут запоминается и используется еженедельной проверкой.
- **Каталог готовых списков.** Проект [awg-manager](https://github.com/hoaxisr/awg-manager) держит все свои заготовки в одном файле и постоянно его правит, поэтому копия, собранная руками, устаревала за считанные дни. Теперь этот файл скачивается раз в неделю, а в пакет вшита копия на 87 записей — на свежей установке без интернета выбор всё равно есть. Скачанное принимается, только если разбирается как непустой каталог: страница-заглушка провайдера не сможет затереть рабочую копию.

### Изменено

- Интерфейс стал ближе к привычной навигации KeeneticOS/NDMS: переработаны шапка, заголовки страниц, боковое меню, состояния наведения и расположение основных действий.
- «Обзор системы» переименован в «Дашборд».
- Перетаскивание строк показывает место вставки и больше не заставляет список прыгать обменом соседних элементов.
- README короче: подробности оформления заменены одной фразой, инструкция публикации убрана.

## [3.0.7-sb.8] — 2026-07-20

### Исправлено

- **Сервис мог не подняться после перезагрузки роутера.** Применение правил вызывает `iptables-restore` и `ipset` как внешние процессы, а ожидание завершения не имело предельного срока; сам `iptables-restore` запускался без `-w` и бесконечно ждал освобождения блокировки xtables. Прошивка при загрузке перенастраивает iptables десятками раз в секунду, поэтому демон вставал намертво, не дойдя до цикла событий, — маршрутизации не было вовсе. Теперь ожидание внешней команды ограничено 30 секундами с эскалацией TERM → KILL, `iptables-restore` вызывается с `-w` и откатом на вызов без ключа для сборок, которые его не знают, а неудача применения не обрывает запуск: сервис поднимается и повторяет попытку с нарастающей задержкой.
- **Клиенты VPN-сервера роутера не попадали в туннели.** Прошивка подменяет адрес источника только для сетей, которые сама направила в туннель, поэтому трафик клиентов входящего WireGuard уходил с внутренним адресом и оставался без ответа. keen-pbr-sb теперь маскарадит выход каждого интерфейса, задействованного в outbound, — это покрывает и sing-box, и нативные WireGuard с AmneziaWG, а заодно гостевые сегменты.

### Добавлено

- **Журнал в файл.** `syslog(3)` в Entware никто не слушает, а стандартный поток ошибок при запуске из init-скрипта теряется, поэтому падения при загрузке не оставляли следов. Появился `/opt/var/log/keen-pbr.log` с отметками времени, сбросом на диск после каждой строки и ротацией на мегабайте, `GET /api/logs` для чтения хвоста и раздел настроек с выключателем записи и выбором подробности — настройка применяется на лету.
- **Задержка для всех интерфейсов.** Раньше измерялись только участники failover-групп; теперь каждый интерфейсный outbound, включая нативные туннели прошивки, опрашивается тем же запросом к `generate_204` раз в 20 секунд. Рядом с цифрой показан возраст замера и кнопка немедленной проверки.
- **Уведомления в шапке.** Колокольчик собирает предупреждения и ошибки из журнала и сообщение о доступном обновлении. Кнопка очистки помечает прочитанным, не трогая сам журнал.
- **Карточка роутера в обзоре системы** — модель, процессор с температурой, память, Wi-Fi, адрес WAN, клиенты, версия прошивки, время работы и средняя нагрузка. Управление маршрутизацией переехало в карточку служб.
- **Вход учётной записью роутера** переключается в настройках; обновление перенесено в конец страницы.

### Изменено

- Обновлены оформление и формулировки интерфейса: единая шапка, более ясная визуальная иерархия, понятные подписи вместо внутренних терминов и человекочитаемое время состояний соединения.

## [3.0.7-sb.6] — 2026-07-19

### Исправлено

- **DNS-detour не работал на практике, из-за чего пропадал доступ к сайтам из списков.** Метка, добавленная в sb.5, перекидывала запросы dnsmasq в туннель уже после того, как ядро выбрало адрес источника: пакет уходил в туннель с адресом WAN, пир его не принимал, ответ не возвращался. Резолв молча падал, IP-адреса не попадали в ipset, и трафик до сайтов не доходил вовсе. Router-originated detour-трафик теперь помечается отдельным битом `0x01000000` (вне пользовательской маски fwmark) и маскарадится на выходе цепочкой `KeenPbrSnat` в `nat POSTROUTING` — источником становится адрес туннеля. Для nftables добавлена цепочка `router_origin_snat` в hook postrouting.

### Изменено

- Интерфейс получил знакомую структуру KeeneticOS/NDMS, компактное меню, плоские таблицы и более предсказуемые формы. Состояние служб и задержка транспортов вынесены на дашборд.
- Управление транспортами переведено на тумблеры, а порядок правил — на перетаскивание за ручку. Панели состояния и массовых действий больше не перекрывают содержимое.

## [3.0.7-sb.5] — 2026-07-19

### Добавлено

- **Принудительный DNS клиентов (Client DNS enforcement).** Новая опция `dns.client_dns_enforcement` и переключатель в общих настройках веб-интерфейса: обычный DNS (порт 53) от клиентов прозрачно перенаправляется на резолвер роутера (nat REDIRECT), а DNS-over-TLS (порт 853) блокируется. Это закрывает главный источник «утечек» доменной маршрутизации — Secure DNS/DoH-клиенты, резолвящие домены мимо dnsmasq, из-за чего IP-адреса не попадали в ipset и трафик шёл напрямую. DoH на порту 443 универсально заблокировать нельзя — рекомендация отключить Secure DNS в браузерах сохраняется в подсказке интерфейса.
- Первая полная переработка интерфейса: синяя палитра, единая навигация, формы, диалоги, таблицы, адаптивная компоновка и фактический индикатор состояния nfqws2.
- Фактическая задержка urltest в карточках транспортов и interface-outbound.
- Отдельная кнопка штатного перезапуска каждого управляемого транспорта.

### Изменено

- Восстановлен подробный основной README с описанием архитектуры, сценариев использования, установки и быстрого старта; новые сведения добавлены без сокращения прежнего текста.
- Периодический опрос nfqws2 теперь полностью пассивен и определяет здоровье по процессу и активной NFQUEUE 300, а не по ошибочной строке init-скрипта.
- Улучшены элементы управления и визуальная обратная связь панели.
- **Kill-switch по умолчанию для туннельных outbound.** Для interface-outbound без шлюза (sing-box TUN, WireGuard/AmneziaWG) `strict_enforcement` теперь по умолчанию включён: при падении или перезапуске туннеля помеченный трафик блокируется unreachable-маршрутом, а не «проваливается» в прямое подключение с настоящим IP. Явные значения `strict_enforcement` на уровне daemon или outbound по-прежнему имеют приоритет — обратите внимание, что явно записанное `"strict_enforcement": false` в `daemon` отключает новое поведение.

### Исправлено

- Ложное состояние «nfqws2 остановлен» при живом процессе и пустом `/opt/var/run/nfqws2.pid`.
- Ошибка restart nfqws2, при которой новый процесс запускался до освобождения очереди 300 и завершался с `nfq_create_queue(): Operation not permitted`.
- При явно запрошенном restart/stop PID-файл безопасно восстанавливается только для единственного найденного процесса; restart ожидает освобождения процесса и NFQUEUE перед новым запуском.
- **DNS detour не работал для запросов самого роутера.** Цепочка маркировки существовала только в `mangle PREROUTING`, поэтому запросы dnsmasq к upstream-серверам с `detour` (например, `8.8.8.8` через AWG или `1.1.1.1` через VLESS) уходили в WAN открытым текстом и могли перехватываться провайдером. Добавлена цепочка `KeenPbrOutput` в `mangle OUTPUT` (nftables: chain `output` типа `route`), которая маркирует локально порождённый DNS-трафик, после чего он корректно перенаправляется через detour-туннель.
- **Перезапуск транспорта мог оставить его выключенным.** Действия транспорта выполнялись с контекстом HTTP-запроса, а `SingBox.Up()` по отмене контекста убивает только что запущенный процесс: если браузер обрывал запрос за время рестарта (до ~15 с), туннель оставался down. Действия переведены на независимый контекст с таймаутом 90 с.
- **Кнопка перезапуска транспорта вела себя непонятно.** Во время рестарта она исчезала (транспорт кратковременно уходит в down), не показывала прогресс, а сама операция блокировала кнопки всех остальных карточек. Теперь кнопка остаётся на месте, крутит иконку и блокирует только свою карточку.
- **Номер очереди nfqws2 был зашит в код.** Проверка здоровья и подтверждение start/restart всегда смотрели на очередь 300, поэтому при изменении `NFQUEUE_NUM` через веб-интерфейс служба показывалась остановленной, а успешный запуск — ошибкой. Значение читается из `nfqws2.conf`.
- **Проверка обновления из веб-интерфейса падала с «GitHub вернул некорректный тег выпуска».** Тег и ссылки на ассеты извлекались из ответа GitHub построчно (`grep | cut -d '\"' -f 4`), что работает только для форматированного JSON; при компактном ответе разбирался посторонний фрагмент. Разбор `self-update.sh` и `install.sh` теперь не зависит от форматирования ответа.
- **Вендоренные CMake-модули не попадали в репозиторий.** Из-за правила `*.cmake` в `.gitignore` файлы вроде `third_party/fmt/support/cmake/JoinPaths.cmake` и `third_party/cpptrace/cmake/*.cmake` не коммитились, и сборка из свежего клона падала на этапе configure.

## [3.0.7-sb.4] — 2026-07-18

### Добавлено

- Отдельный transport-manager для управляемых sing-box TUN.
- Импорт share-link и произвольного sing-box outbound JSON.
- Поддержка VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC, AnyTLS, SOCKS и HTTP(S)-прокси через sing-box.
- Нативные интерфейсы Keenetic, WireGuard и AmneziaWG.
- `urltest`/failover-цепочки между несколькими интерфейсами.
- Детерминированный уникальный `/30` для каждого sing-box TUN и ручное поле `tun_address`.
- Health-check транспорта по фактическому состоянию urltest keen-pbr, а не только по наличию процесса.
- Кнопка исключения адреса VPN-сервера из туннеля для защиты от маршрутной петли.
- Настраиваемые bootstrap DNS.
- Текстовые URL-списки и бинарные sing-box rule-set `.srs`.
- Настраиваемое автоматическое обновление URL-списков.
- Мастер быстрого создания правил маршрутизации и DNS при добавлении списка.
- Импорт и экспорт списков и правил маршрутизации.
- Страница активных соединений: адреса, порты, состояния, устройства Keenetic, домены при наличии DNS-сопоставления, маршрут и автообновление. История ограничена 1500 соединениями.
- Русская авторизация веб-интерфейса с HttpOnly cookie-сессией.
- Интерактивные русские установщик и деинсталлятор.
- Установка проверенной версии sing-box `1.13.14` и предупреждение о непроверенных новых версиях.
- Опциональная установка `nfqws2-keenetic`.
- Встроенная страница nfqws2: служба, конфигурация, стратегии, списки, Lua-скрипты, журналы, обновление пакета и проверка сайтов.
- Редактирование штатных сжатых Lua-скриптов `*.lua.gz` с прозрачной распаковкой и обратным сжатием.
- Проверка и установка обновлений keen-pbr-sb из веб-интерфейса.
- Показ заметок GitHub Release и ссылки на полный `CHANGELOG.md` перед веб-обновлением.

### Изменено

- Брендинг веб-интерфейса заменён на `keen-pbr-sb`.
- FORWARD-правила управляемых TUN добавляются в конец цепочки, а не перед пользовательскими правилами.
- README стал русским основным описанием форка.
- Удалён тяжёлый локальный видеоролик upstream-документации; документация использует внешнюю ссылку на оригинал.
- GitHub Actions исключены из поставки: AArch64 IPK публикуется вручную в GitHub Release.

### Исправлено

- Конфликт одинакового TUN-адреса `172.19.0.1/30` у нескольких одновременных sing-box-транспортов.
- Зомби-состояние «процесс жив, туннель не работает».
- Накопление осиротевших процессов и FORWARD-правил после аварийного завершения transport-manager.
- Распознавание `sing-box.real`, запускаемого через загрузчик Entware `ld-2.27.so`.
- Возможная маршрутная петля через адрес прокси-сервера.
- Ошибка sing-box `unknown field dns_mode`.
- Поиск sing-box только по `/opt/bin/sing-box` без учёта выбранного пользовательского пути.
- Повторный запуск установщика, необходимый в ранних сборках.
- Установка nfqws2 через HTTPS при наличии `wget-nossl` вместо `wget-ssl`.
- Права списков nfqws2 после редактирования из веб-интерфейса.
- Пустой список Lua-файлов nfqws2 из-за расширения `.lua.gz`.
- Выбор и индикация активной стратегии nfqws2.
- Исчезающие уведомления после применения стратегии, перезапуска и обновления nfqws2.
- Обрезание значений и кнопок в карточке транспорта.
- Потеря пользовательской конфигурации при переустановке IPK.
- Ложное предложение отката, когда установленная версия новее последнего GitHub Release.

## [3.0.7-sb.3] — 2026-07-18

Первый полный публичный выпуск форка для Entware `aarch64-3.10`.

### Добавлено

- Управляемые sing-box-транспорты.
- VLESS, VMess, Trojan, Shadowsocks и другие протоколы sing-box.
- Нативные WireGuard/AmneziaWG-интерфейсы.
- URLTest failover.
- Keenetic DNS Override и bootstrap DNS.
- Бинарные SRS-списки.
- Страница активных соединений.
- Импорт и экспорт списков и правил.
- Встроенное управление nfqws2 и набор стратегий.
- Проверенная версия sing-box `1.13.14`.

### Ограничения

- Ряд функций присутствовал в первой реализации, но ещё требовал исправлений, перечисленных в `3.0.7-sb.4`.

## 3.0.7-sb.2 — 2026-07-18

Промежуточная локальная сборка без отдельного публичного GitHub Release.

### Изменено

- Очищена структура исходников и исключены ненужные сборочные файлы.
- Подготовлена ручная публикация IPK и `SHA256SUMS` без GitHub Actions.
- Уточнены имена пакета и тегов форка.

## [3.0.7-sb.1] — 2026-07-18

Первый публичный тестовый пакет форка для Entware `aarch64-3.10`.

### Добавлено

- Первичная интеграция дополнений keen-pbr-sb в Keenetic IPK.
- Первый вариант однострочного установщика.
- Публикация AArch64-пакета и файла `SHA256SUMS`.

### Ограничения

- Выпуск имел экспериментальный статус и не рекомендуется для новой установки.
- Заметки GitHub Release для этой версии не заполнялись.

[3.0.7-sb.4]: https://github.com/blindtechnique/keen-pbr-sb/releases/tag/v3.0.7-sb.4
[3.0.7-sb.3]: https://github.com/blindtechnique/keen-pbr-sb/releases/tag/v3.0.7-sb.3
[3.0.7-sb.1]: https://github.com/blindtechnique/keen-pbr-sb/releases/tag/3.0.7-sb1

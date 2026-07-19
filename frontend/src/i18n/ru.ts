export const ruTranslation = {
  nfqws: {
    description:
      "Управление nfqws2, стратегиями, конфигурацией, списками, Lua-скриптами и журналами.",
    refresh: "Обновить",
    service: "Служба nfqws2",
    version: "Установленная версия: {{version}}",
    running: "Работает",
    stopped: "Остановлена",
    start: "Запустить",
    stop: "Остановить",
    restart: "Перезапустить",
    reload: "Перечитать конфигурацию",
    upgrade: "Обновить пакет",
    operationResult: "Результат операции nfqws2",
    operationCompleted: "Операция успешно выполнена.",
    closeResult: "Закрыть сообщение",
    tabs: {
      settings: "Настройки",
      strategies: "Стратегии",
      lists: "Списки",
      lua: "Lua-скрипты",
      logs: "Журналы",
      check: "Проверка сайта",
    },
    notInstalled: {
      title: "nfqws2 не установлен",
      description:
        "Раздел останется доступным, но управление появится после установки официального пакета nfqws2-keenetic.",
      ourInstaller: "Через установщик keen-pbr-sb (рекомендуется)",
      original: "Через оригинальный репозиторий nfqws2",
    },
    settingsTitle: "Параметры nfqws2",
    settingsDescription:
      "Форма сохраняет изменения в /opt/etc/nfqws2/nfqws2.conf, сохраняя остальные строки конфигурации.",
    strategiesTitle: "Стратегии",
    strategiesDescription:
      "Выберите предустановленную стратегию, измените её, сохраните как пользовательскую или примените к nfqws2.",
    builtin: "предустановлена",
    activeStrategy: "активна",
    activeStrategyLabel: "Сейчас применяется:",
    activeStrategyCustom: "изменённая вручную конфигурация",
    selectedForEditing: "Для редактирования выбрана «{{name}}»",
    strategyAppliedAndRestarted:
      "Стратегия применена, служба nfqws2 перезапущена.",
    addStrategy: "Новая стратегия",
    strategyName: "Название новой стратегии",
    applyStrategy: "Применить",
    saveStrategy: "Сохранить",
    confirmDelete: "Удалить выбранный файл или стратегию?",
    fileName: "Имя нового файла без расширения",
    newFile: "Новый файл",
    save: "Сохранить",
    saved: "Изменения сохранены",
    clearLog: "Очистить журнал",
    confirmClearLog: "Очистить выбранный журнал nfqws2?",
    logCleared: "Журнал очищен",
    configMissing: "Файл nfqws2.conf не найден.",
    checkTitle: "Проверка доступности сайта",
    checkDescription:
      "Проверяет HTTP-ответ с маршрутизатора. Это аналог проверки из оригинального nfqws-web.",
    check: "Проверить",
    reachable: "Сайт вернул читаемый ответ.",
    unreachable: "Сайт недоступен или не вернул читаемый ответ.",
  },
  configTransfer: {
    export: "Экспорт",
    import: "Импорт",
    invalidFormat: "Файл не является совместимым экспортом keen-pbr-sb.",
    replaceLists:
      "Заменить все существующие списки? Нажмите «Отмена», чтобы объединить списки.",
    replaceRules:
      "Заменить все правила маршрутизации? Нажмите «Отмена», чтобы добавить импортированные правила в конец.",
    mapOutbound:
      "В системе нет outbound «{{missing}}». Укажите один из существующих: {{available}}",
    outboundRequired:
      "Для каждого импортированного правила необходимо выбрать существующий outbound.",
  },
  auth: {
    title: "Вход в keen-pbr-sb",
    description: "Авторизуйтесь, чтобы открыть управление маршрутизацией.",
    username: "Имя пользователя",
    password: "Пароль",
    signIn: "Войти",
    signingIn: "Вход…",
    signOut: "Выйти",
    invalidCredentials: "Неверное имя пользователя или пароль.",
    unavailable: "Сервис авторизации недоступен.",
    credentialsHint:
      "Данные задаются установщиком keen-pbr-sb. Это отдельная локальная учётная запись; источник указан в README.",
  },
  common: {
    language: "Язык",
    theme: "Тема",
    enabled: "Включено",
    disabled: "Выключено",
    close: "Закрыть",
    cancel: "Отмена",
    copy: "Копировать",
    copied: "Скопировано",
    clipboardUnavailable: "Буфер обмена недоступен",
    edit: "Изменить",
    delete: "Удалить",
    moveUp: "Переместить вверх",
    moveDown: "Переместить вниз",
    unableToLoadData: "Не удалось загрузить данные",
    loadErrorDescription:
      "Сейчас не получается загрузить данные. Попробуйте обновить страницу.",
    noneShort: "-",
    multiSelectList: {
      addItem: "Добавить элемент",
      emptyMessage: "Элементы не найдены.",
      availableItems: "Доступные элементы",
      noItemsSelected: "Элементы не выбраны",
      addFirstItem:
        "Добавьте первый элемент, чтобы начать формировать этот список.",
      removeItem: "Удалить {{item}}",
    },
    listUsage: {
      usedElsewhere: "Используется ещё в: {{summary}}",
    },
    interfacePicker: {
      open: "Открыть выбор интерфейса",
      empty: "Интерфейсы не найдены.",
      notExists: "(не существует)",
      notFound: "Интерфейс не существует.",
    },
    validation: {
      tagNamePattern:
        "Может содержать только a-z, 0-9 и подчёркивание. Максимум 24 символа, должен начинаться с буквы.",
    },
    selection: {
      selectAll: "Выбрать все видимые строки",
      selectRow: "Выбрать {{rowLabel}}",
    },
  },
  runtime: {
    healthy: "Исправен",
    notHealthy: "Неисправен",
    activeOutbound: "Активный outbound {{value}}",
    activeInterface: "Активный {{value}}",
    outboundStatus: {
      healthy: "Исправен",
      degraded: "Деградирован",
      unavailable: "Недоступен",
      unknown: "Неизвестно",
    },
    interfaceStatus: {
      active: "Активен",
      backup: "Резервный",
      degraded: "Деградирован",
      unavailable: "Недоступен",
      unknown: "Неизвестно",
    },
    fallback: {
      table: "Таблица маршрутизации {{value}}",
      blackhole: "Блокировать весь входящий трафик",
    },
  },
  language: {
    selectorAria: "Выбор языка",
    english: "Английский",
    russian: "Русский",
  },
  theme: {
    selectorAria: "Выбор темы",
    useSystem: "Как в системе",
    light: "Светлая",
    dark: "Тёмная",
  },
  nav: {
    groups: {
      general: "Общее",
      internet: "Интернет",
      networkRules: "Правила трафика",
    },
    items: {
      systemMonitor: "Обзор системы",
      settings: "Настройки",
      outbounds: "Outbounds (выходы)",
      transports: "Транспорты",
      connections: "Соединения",
      dnsServers: "DNS-серверы",
      lists: "Списки",
      routingRules: "Правила маршрутизации",
      dnsRules: "DNS-правила",
    },
  },
  connections: {
    age: {
      now: "только что",
      seconds: "{{count}} с назад",
      minutes: "{{count}} мин назад",
      hours: "{{count}} ч назад",
    },
    deviceCount: "Устройств: {{count}}",
    routeDirect: "Напрямую",
    empty: "Соединений нет",
    title: "Соединения",
    description:
      "Активные соединения и до 1500 последних записей. Для DNS-запросов через keen-pbr рядом с точным IP показывается последний известный домен. Данные обновляются каждые 3 секунды.",
    filter: "Фильтр по устройству, домену, адресу, состоянию или маршруту",
    activeOnly: "Только активные",
    sort: "Сортировка",
    sortRecent: "Сначала новые",
    sortSource: "По устройству",
    sortDestination: "По назначению",
    sortRoute: "По маршруту",
    state: "Состояние",
    device: "Устройство / источник",
    destination: "Назначение",
    protocol: "Протокол",
    route: "Маршрут",
  },
  transports: {
    dnsDetour: "DNS через этот туннель",
    singBoxMissing: {
      title: "sing-box не установлен",
      description:
        "Для VLESS, VMess, Trojan, Shadowsocks и других управляемых proxy-транспортов установите sing-box. Запустите установщик keen-pbr-sb по SSH и выберите протестированную версию.",
    },
    title: "Транспорты",
    description:
      "Нативные и управляемые туннельные интерфейсы для outbounds keen-pbr.",
    refresh: "Обновить",
    add: "Добавить транспорт",
    unavailable: "Менеджер транспортов недоступен",
    empty: "Транспорты пока не настроены.",
    interface: "Интерфейс",
    server: "Сервер",
    loopProtection: {
      action: "Исключить сервер из туннеля",
      confirm:
        "Добавить {{server}} в первый pass-through список? Будут созданы список transport_servers, outbound transport_bypass типа ignore и самое первое правило маршрутизации.",
      saved: "Защита от маршрутной петли добавлена",
      tagConflict:
        "Тег {{tag}} уже занят outbound другого типа. Переименуйте его и повторите.",
    },
    pid: "PID",
    updatedAt: "Обновлено",
    autoRecovery: "Автовосстановление",
    enabled: "Включено",
    paused: "Остановлено вручную",
    retryCount: "Попыток восстановления",
    nextRetryAt: "Следующая попытка",
    start: "Запустить",
    stop: "Остановить",
    restart: "Перезапустить",
    latency: "Задержка",
    latencyUnavailable: "нет замера",
    started: "Запуск транспорта запрошен",
    stopped: "Остановка транспорта запрошена",
    restarted: "Перезапуск транспорта запрошен",
    nativeManagedExternally:
      "Этот нативный интерфейс управляется KeeneticOS или другим сервисом.",
    deleteTitle: "Удалить транспорт?",
    deleteDescription:
      "Управляемый процесс будет остановлен, а его конфигурация удалена.",
    configMessages: {
      create: "Транспорт создан",
      update: "Транспорт обновлён",
      delete: "Транспорт удалён",
    },
    form: {
      createOutbound: "Сразу создать outbound",
      createOutboundHint: "Создаст interface-outbound с тем же тегом — транспорт сразу можно выбрать в правилах маршрутизации.",
      outboundExists: "Outbound с тегом {{tag}} уже существует",
      createTitle: "Добавить транспорт",
      editTitle: "Изменить транспорт",
      description:
        "Добавьте нативный интерфейс или изолированный proxy TUN для keen-pbr.",
      tag: "Тег",
      tagHint:
        "От 1 до 24 символов: сначала строчная латинская буква, затем только a–z, 0–9 и подчёркивание. Например: my_transport.",
      type: "Тип",
      native: "Нативный интерфейс",
      singBox: "Подключение sing-box",
      singBoxLegacy: "sing-box (старый формат VLESS)",
      interface: "Имя интерфейса",
      autoStart: "Запускать автоматически",
      shareLink: "Ссылка подключения",
      shareLinkHint:
        "Поддерживаются ссылки VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC, AnyTLS, SOCKS и HTTP-прокси.",
      outboundJson: "Outbound JSON для sing-box",
      outboundJsonHint:
        "Расширенный режим для любого outbound, поддерживаемого установленной версией sing-box. Тег назначается автоматически.",
      keepConnection: "Оставьте пустым, чтобы сохранить прежнее подключение",
      server: "Сервер",
      port: "Порт",
      uuid: "UUID",
      serverName: "Имя сервера REALITY",
      publicKey: "Публичный ключ REALITY",
      shortId: "Short ID REALITY",
      fingerprint: "Отпечаток uTLS",
      mtu: "MTU",
      bootstrapDns: "Bootstrap DNS",
      tunAddress: "Адрес TUN (необязательно)",
      tunAddressPlaceholder: "Автоматически из отдельной /30-подсети",
      tunAddressHint:
        "Оставьте пустым: адрес будет стабильно выбран из 172.19.0.0/16 по тегу. Для ручной настройки укажите адрес узла с префиксом /30, например 10.77.0.1/30.",
      bootstrapDnsHint:
        "IP-адреса DNS-серверов по одному в строке. Они используются для разрешения имени VPN-сервера до запуска туннеля; порт можно указать через двоеточие.",
      keepSecret: "Оставьте пустым, чтобы сохранить прежний UUID",
      saving: "Сохранение…",
      save: "Сохранить",
    },
    routing: {
      title: "Транспорт ещё не является маршрутом",
      description:
        "Сначала свяжите интерфейс транспорта с outbound типа «Интерфейс». Для автоматического переключения создайте затем outbound типа URLTest и добавьте в его группы два или больше interface-outbound.",
      createOutbound: "Создать интерфейсный outbound",
      createFailover: "Создать failover (URLTest)",
      bindOutbound: "Создать outbound для этого интерфейса",
    },
    states: {
      connected: "Подключено",
      down: "Остановлен",
      starting: "Запускается",
      up: "Работает",
      degraded: "Есть проблема",
    },
  },
  brand: {
    logoAlt: "логотип keen-pbr-sb",
    tagline: "Пакет для пакетов с пакетами",
    openMenu: "Открыть меню",
  },
  warning: {
    draftChanged:
      "Конфигурация была изменена. Сохраните её на диск для применения.",
    actions: {
      applying: "Применение...",
      apply: "Применить",
      applyingAndRestarting: "Применение и перезапуск...",
      applyAndRestart: "Применить и перезапустить",
      restarting: "Перезапуск...",
      restart: "Перезапустить",
    },
    compact: {
      keenRestartRequired: "Несохранённые изменения",
      keenRestartRequiredDescription:
        "Настройки изменены. Примените их для перезапуска keen-pbr.",
      keenAndDnsmasqRestartRequired: "Конфигурация устарела",
      keenAndDnsmasqRestartRequiredDescription:
        "Примените настройки, чтобы синхронизировать keen-pbr и dnsmasq.",
      dnsmasqRestartRequired: "Конфигурация DNS-сервера устарела",
      dnsmasqRestartRequiredDescription:
        "dnsmasq использует устаревший конфиг. Требуется перезапуск.",
      dnsmasqRestarting: "Перезапуск dnsmasq...",
      dnsmasqRestartingDescription:
        "DNS-сервер перезапускается, подождите немного.",
      dnsmasqUnavailable: "проверка dnsmasq не прошла",
      dnsmasqUnavailableDescription:
        "keen-pbr не смог запросить TXT-запись состояния dnsmasq. Если статус не меняется, попробуйте применить и перезапустить.",
      staleAfterTimeout:
        "dnsmasq в последний раз перезагружался: {{actualTs}}. Если статус не меняется, перезапустите маршрутизацию.",
    },
    full: {
      unsavedTitle: "Конфигурация не сохранена",
      staleTitle: "dnsmasq использует устаревший конфиг резолвера",
      staleDescription:
        "Ожидаемый хеш резолвера ({{expected}}…) не совпадает с активным хешем dnsmasq ({{actual}}…).",
    },
  },
  overview: {
    router: {
      title: "Роутер",
      unavailable: "Сведения о роутере недоступны: прошивка не отвечает на служебные запросы.",
      cpu: "Процессор",
      memory: "Память",
      memoryValue: "{{used}} МБ / {{total}} МБ ({{percent}}%)",
      memoryTotalOnly: "{{total}} МБ",
      wifi: "Wi-Fi",
      wan: "Адрес WAN",
      clients: "Клиенты",
      clientsValue: "{{active}} активно / {{total}} всего",
      firmware: "Версия ПО",
      uptime: "Время работы",
      uptimeValue: "{{days}} д {{hours}} ч {{minutes}} мин",
      loadAverage: "Средняя нагрузка",
    },
    services: {
      version: "Версия {{version}}, сборка {{build}}",
      unknown: "Состояние неизвестно",
      restart: "Перезапустить",
      restartRequested: "Перезапуск запрошен",
      restartFailed: "Не удалось перезапустить",
      title: "Службы",
      singbox: "sing-box",
      nfqws: "nfqws2",
      transportsRunning: "Запущено {{running}} из {{total}}",
      noTransports: "Транспорты не настроены",
      notInstalled: "Не установлен",
      running: "Служба запущена",
      stopped: "Служба остановлена",
      badgeUp: "Работает",
      badgeDown: "Остановлен",
      badgeAbsent: "Нет",
    },
    pageDescription:
      "Обзор состояния маршрутизации, конфигурации и активных outbounds",
    runtime: {
      title: "Маршрутизация",
      description: "Управление policy-based routing.",
      loadError: "Не удалось загрузить состояние маршрутизации.",
      version: "Версия",
      router: "Роутер",
      status: "Статус маршрутизации",
      dnsmasqHealthy: "dnsmasq исправен",
      dnsmasqWaiting: "dnsmasq перезагружается",
      dnsmasqStale: "dnsmasq требуется перезапуск",
      dnsmasqUnavailable: "проверка dnsmasq не прошла",
      dnsmasqUnknown: "статус dnsmasq неизвестен",
      actions: {
        start: "Запустить",
        stop: "Остановить",
        restart: "Перезапустить",
      },
    },
    outbounds: {
      members: "{{count}} в группе",
      kind: {
        failover: "Failover",
        table: "Таблица",
        blackhole: "Блокировка",
        ignore: "Без изменений",
        interface: "Интерфейс",
      },
      status: {
        healthy: "Исправен",
        degraded: "Не работает",
        unknown: "Неизвестно",
        misconfigured: "Ошибка настройки",
      },
      member: {
        active: "Активен",
        backup: "Резервный",
        unavailable: "Недоступен",
        unknown: "Неизвестно",
      },
      title: "Состояние outbounds",
      loadError: "Не удалось загрузить состояние outbounds.",
      emptyTitle: "Outbounds не настроены",
      emptyDescription: "Добавьте outbounds, чтобы увидеть проверки состояния.",
      inUse: "Используется",
      urltestTitle: "urltest",
      headers: {
        tag: "Тег",
        destination: "Назначение",
        status: "Статус",
      },
      destination: {
        interface: "Интерфейс {{name}}",
        interfaceWithGateway: "Интерфейс {{name}} (шлюз: {{gateway}})",
        table: "Таблица {{value}}",
        outbound: "Outbound {{name}}",
      },
    },
    routing: {
      title: "Диагностика",
      loadError: "Не удалось загрузить проверки маршрутизации.",
      emptyTitle: "Проверки маршрутизации ещё не появились",
      emptyDescription:
        "Проверки маршрутизации появятся после следующего применения или перезапуска маршрутизации.",
      showHealthyEntries: "Показать и здоровые записи",
      allHealthyTitle: "Всё в порядке",
      allHealthyDescription:
        "Сейчас нет проблемных записей в диагностике маршрутизации.",
      noChecksTitle: "Проверок нет",
      noChecksDescription:
        "Для диагностики маршрутизации нет записей для отображения.",
      sections: {
        firewall: "Firewall",
        routes: "Маршруты",
        policies: "Политики",
      },
      chain: "chain",
      prerouting: "prerouting",
      defaultRoute: "default",
      ipv4: "IPv4",
      ipv6: "IPv6",
      yes: "да",
      no: "нет",
      tableLabel: "таблица {{value}}",
      priorityLabel: "приоритет {{value}}",
      fwmarkLabel: "fwmark {{value}}",
      fwmarkExpectedActual: "ожидалось {{expected}}, получено {{actual}}",
      actualLabel: "фактически {{value}}",
      routeTypeFallback: "маршрут",
      routeVia: "через {{value}}",
      routeGateway: "шлюз {{value}}",
      routeMetric: "метрика {{value}}",
      issues: {
        tableMissing: "таблица отсутствует",
        defaultRouteMissing: "маршрут по умолчанию отсутствует",
        interfaceMismatch: "несовпадение интерфейса",
        gatewayMismatch: "несовпадение шлюза",
      },
    },
    diagnosticsDownload: {
      button: "Скачать файл диагностики",
      modal: {
        title: "Внимание, чувствительные данные!",
        description: "Файл диагностики содержит следующие данные:",
        items: {
          config:
            "Ваш конфигурационный файл целиком (включая используемые списки)",
          serviceHealth: "Состояние сервиса",
          routingHealth: "Состояние маршрутизации",
          outbounds: "Состояние outbounds",
          names: "Наименования списков, outbounds, интерфейсов",
        },
        trustWarning:
          "Пожалуйста, передавайте данный файл только тому, кому вы доверяете.",
        hideListsOption: "Скрыть содержимое списков и URL-адреса на списки",
        downloadAction: "Скачать файл диагностики",
      },
    },
    dnsCheck: {
      card: {
        title: "Проверка DNS",
        description:
          "Проверяет, что DNS-разрешение через keen-pbr работает корректно - из этого браузера или с другого устройства.",
        disabledDescription:
          "Включите опцию `dns.dns_test_server` в конфигурационном файле, чтобы включить самопроверку DNS.",
        configuredServers: "Настроенные DNS-серверы",
        noServers:
          "На странице DNS-серверов не определено ни одного DNS-сервера.",
        via: "через {{detour}}",
        checking: "Проверка...",
        runAgain: "Запустить снова",
        testFromPc: "Проверить с другого устройства",
      },
      modal: {
        title: "Проверить DNS с другого устройства",
        description:
          "Запустите сгенерированную команду `nslookup` на ПК или телефоне, пока это окно остаётся открытым.",
        copyCommand: "Скопируйте и выполните эту команду:",
        warning:
          "Тестовый DNS-запрос ещё не поступил. Убедитесь, что устройство использует DNS вашего роутера, и попробуйте команду ещё раз.",
        copyAria: "Скопировать команду",
      },
      status: {
        disabled: "Встроенный DNS-пробник отключён в конфиге.",
        browserSuccess: "DNS-запрос из браузера достиг dnsmasq.",
        manualProbeSuccess: "DNS-запрос от устройства достиг dnsmasq.",
        browserProbeFail:
          "Запрос браузера завершился, но DNS-пробник не увидел lookup.",
        sseUnavailable:
          "Поток событий DNS в реальном времени недоступен, поэтому проверка не смогла запуститься.",
        browserFail:
          "Запрос браузера выполнился, но DNS lookup не был замечен.",
        sseFail: "Поток событий DNS в реальном времени не подключён.",
        browserChecking: "Проверяем DNS-путь браузера...",
        browserUnknown: "Статус DNS в браузере пока неизвестен.",
        manualSuccess: "DNS-запрос от устройства достиг dnsmasq.",
        manualWaiting: "Ожидание вашей ручной команды nslookup...",
        manualIncomplete: "Ручной тест устройства ещё не завершён.",
      },
    },
    routingTest: {
      title: "Куда пойдёт этот трафик?",
      placeholder: "напр. google.com или 1.2.3.4",
      submit: "Проверить маршрут",
      invalidTarget: "Введите корректный домен или IP-адрес.",
      requestFailed: "Проверка маршрута не удалась. Попробуйте ещё раз.",
      emptyTitle: "Маршрут не найден",
      emptyDescription: "Попробуйте другой домен или IP-адрес.",
    },
    routingDiagnostics: {
      noMatchingRule:
        "Для целевых списков не найдено подходящего правила маршрутизации.",
      hostLabel: 'Хост "{{target}}"',
      inRuleLists: "Есть в доменных/IP-списках правила?",
      showAllRules: "Показывать все правила",
      listMatch: "{{list}}: {{via}}",
      noConditions: "Без дополнительных условий",
      conditions: {
        lists: "Списки",
        proto: "Протокол",
        sourceIp: "IP источника",
        destinationIp: "IP назначения",
        sourcePort: "Порт источника",
        destinationPort: "Порт назначения",
      },
    },
    routingLegend: {
      title: "Условные обозначения",
      inLists: "Есть в доменных/IP-списках",
      notInLists: "Нет в доменных/IP-списках",
      inIpsetAndLists: "Есть в IPSet и в списках",
      notInIpsetAndNotInLists: "Нет в IPSet и нет в списках",
      inIpsetButShouldNotBe: "Есть в IPSet, хотя не должно быть",
      notInIpsetButShouldBe: "Нет в IPSet, хотя должно быть",
    },
  },
  pages: {
    settings: {
      auth: {
        title: "Вход в веб-интерфейс",
        description: "Кто и как подтверждает вход в keen-pbr-sb.",
        enabled: "Требовать вход",
        provider: "Способ проверки",
        providerRouter: "Учётная запись роутера",
        providerLocal: "Отдельный пароль keen-pbr-sb",
        providerRouterHint: "Логин и пароль проверяются самой прошивкой Keenetic. keen-pbr-sb пароль не хранит.",
        providerLocalHint: "Логин и пароль хранятся в auth.json на роутере.",
        endpoint: "Адрес веб-интерфейса роутера",
        username: "Логин",
        password: "Пароль",
        verifyHint: "Укажите учётные данные роутера — они будут проверены перед сохранением, чтобы вход не оказался заблокирован.",
        localStoreHint: "Задайте логин и пароль, которыми будете входить в keen-pbr-sb.",
        save: "Сохранить способ входа",
        saved: "Настройки входа сохранены, войдите заново",
      },
      title: "Настройки",
      description:
        "Глобальные настройки, действующие на все outbounds и правила.",
      saved:
        "Настройки сохранены в черновик. Примените новый конфиг, чтобы записать их.",
      general: {
        title: "Общие",
        description: "Поведение по умолчанию для всех outbounds.",
        strictEnforcementLabel:
          "Блокировать трафик при падении outbound (kill-switch)",
        strictEnforcementHint:
          "Если VPN или интерфейс отключится, трафик по его правилам будет заблокирован, а не отправлен через основную таблицу маршрутизации. Можно переопределить для каждого outbound.",
        skipMarkedPacketsLabel: "Не обрабатывать маркированные пакеты",
        skipMarkedPacketsHint:
          "Игнорировать пакеты, у которых уже есть fwmark проставленный другими правилами firewall, чтобы policy routing не обрабатывал их повторно.",
        ipv6EnabledLabel: "Включить поддержку IPv6",
        ipv6EnabledHint:
          "Создавать IPv6-наборы firewall и IPv6-цели dnsmasq. Отключите на старых прошивках без поддержки IPv6 netfilter.",
        clientDnsEnforcementLabel: "Принудительно направлять DNS клиентов через роутер",
        clientDnsEnforcementHint:
          "Прозрачно перенаправлять обычный DNS (порт 53) от клиентов на резолвер роутера и блокировать DNS-over-TLS (порт 853), чтобы Secure DNS в браузерах не обходил доменную маршрутизацию. DNS-over-HTTPS на порту 443 так заблокировать нельзя — для полного покрытия отключите Secure DNS в браузерах.",
        inboundInterfacesLabel: "Входящие интерфейсы",
        inboundInterfacesHint:
          "Policy routing будет применяться только к пакетам, пришедшим через выбранные интерфейсы. Оставьте поле пустым, чтобы обрабатывать трафик с любых интерфейсов.",
        inboundInterfacesAddAction: "Добавить интерфейс",
        inboundInterfacesLoading: "Загрузка интерфейсов...",
        inboundInterfacesNoAvailable:
          "Больше нет доступных интерфейсов для добавления.",
        inboundInterfacesEmptyTitle: "Входящие интерфейсы не выбраны",
        inboundInterfacesEmptyDescription:
          "Добавьте интерфейсы, если policy routing должен применяться только к определённым входящим интерфейсам.",
        inboundInterfacesLoadError:
          "Живая инвентаризация интерфейсов временно недоступна. Сохранённые значения всё равно можно редактировать.",
        inboundInterfacesStatusUp: "UP",
        inboundInterfacesStatusDown: "DOWN",
        inboundInterfacesStatusLoading: "Загрузка",
        inboundInterfacesStatusMissing: "Отсутствует",
        inboundInterfacesMissingDetail:
          "Этот интерфейс сохранён в конфиге, но сейчас отсутствует в живом списке интерфейсов системы.",
      },
      autoupdate: {
        scheduleHint: "Как часто проверять обновления списков.",
        schedule: {
          hourly: "Каждый час",
          daily: "Каждый день",
          weekly: "Каждую неделю",
          monthly: "Каждый месяц",
          custom: "Своё расписание (cron)",
          atHour: "в {{hour}}:00",
          dayOfMonth: "{{day}}-го числа",
          weekdays: {
            sunday: "По воскресеньям",
            monday: "По понедельникам",
            tuesday: "По вторникам",
            wednesday: "По средам",
            thursday: "По четвергам",
            friday: "По пятницам",
            saturday: "По субботам",
          },
        },
        title: "Автообновление списков",
        description: "Автоматическое обновление удалённых списков.",
        enabledLabel: "Включить автообновление списков",
        enabledHint:
          "Автоматически скачивать обновления удалённых списков и обновлять маршрутизацию при изменениях.",
        cronLabel: "Расписание обновления",
        cronHintPrefix:
          "Как часто проверять обновления. Формат cron. Используйте",
        cronHintSuffix: "для помощи.",
        openInGuru: "Открыть в Crontab Guru",
      },
      softwareUpdate: {
        title: "Обновление keen-pbr-sb",
        description:
          "Проверяет последний опубликованный Release, сверяет SHA256SUMS и устанавливает IPK, сохраняя конфигурацию, транспортные интерфейсы и учётную запись веб-интерфейса.",
        current: "Установлено",
        latest: "Последний выпуск",
        check: "Проверить обновления",
        install: "Установить обновление",
        running:
          "Обновление выполняется. Веб-интерфейс может быть недоступен несколько секунд и подключится снова автоматически.",
        upToDate: "Установлена последняя опубликованная версия.",
        newerThanPublished:
          "Установленная версия новее последнего опубликованного выпуска. Откат предлагаться не будет.",
        changesTitle: "Что изменилось в {{version}}",
        releaseNotesMissing:
          "Для этого выпуска нет кратких заметок. Откройте полный журнал изменений.",
        releasePage: "Страница выпуска",
        fullChangelog: "Полный журнал изменений",
        confirm:
          "Установить keen-pbr-sb {{version}}? Службы маршрутизации и веб-интерфейс будут кратковременно перезапущены. Перед продолжением ознакомьтесь со списком изменений на странице.",
        result: "Журнал обновления",
        waitingForLog: "Обновление запущено, ожидаем первые строки журнала…",
        checkFailed: "Не удалось проверить обновления.",
        startFailed: "Не удалось запустить обновление.",
      },
      advanced: {
        title: "Расширенные настройки маршрутизации",
        description:
          "Расширенные настройки - меняйте только если понимаете, что делаете.",
        fwmarkStartLabel: "Начальное значение firewall mark",
        fwmarkStartHint:
          "Начальное значение fwmark для первого outbound. Каждый следующий outbound получает следующее значение в диапазоне.",
        fwmarkMaskLabel: "Маска firewall mark",
        fwmarkMaskHintPrefix:
          "Битовая маска, определяющая, какие биты используются для fwmark. Должна содержать непрерывный блок hex-цифр",
        fwmarkMaskHintSuffix: "например",
        tableStartLabel: "Начальное значение таблицы маршрутизации IP",
        tableStartHint:
          "ID таблицы маршрутизации для первого outbound. Каждый следующий outbound получает следующий ID.",
      },
      actions: {
        saving: "Сохранение...",
        save: "Сохранить",
      },
    },
    dnsServers: {
      title: "DNS-серверы",
      description: "Upstream DNS-серверы для разрешения доменных имён.",
      keeneticAddress: "Встроенный DNS Keenetic",
      actions: {
        add: "Добавить DNS-сервер",
      },
      empty: {
        title: "DNS-серверов пока нет",
        description:
          "Добавьте DNS-сервер, чтобы настроить upstream-разрешение.",
      },
      loadErrorDescription:
        "Сейчас не получается загрузить DNS-серверы. Попробуйте обновить страницу.",
      headers: {
        name: "Название",
        address: "Адрес",
        outbound: "Outbound",
        actions: "Действия",
      },
      delete: {
        confirmWithReferences:
          'DNS-сервер "{{serverTag}}" сейчас используется в {{count}} правил(е/ах){{fallbackSuffix}}.\nУдалить и автоматически убрать эти ссылки?',
        fallbackSuffix: " и как fallback",
      },
      deleteDialog: {
        title: "Удалить DNS-серверы?",
        description:
          "При подтверждении операции будут произведены следующие действия:",
        confirm: "Удалить",
        items: {
          serverPrefix: "DNS-сервер",
          serverSuffix: "будет удалён.",
          dnsRule: "DNS-правило #{{number}} будет удалено.",
          fallback: "Fallback DNS будет изменён.",
        },
      },
      bulk: {
        selected: "Выбрано: {{count}}",
        delete: "Удалить выбранные",
        confirmDelete:
          "Удалить DNS-серверы: {{tags}}?\nАвтоматически убрать ссылки из правил?",
      },
      none: "нет",
    },
    dnsServerUpsert: {
      createTitle: "Создать DNS-сервер",
      editTitle: "Изменить DNS-сервер",
      missingCardDescription: "Запрошенный DNS-сервер не найден.",
      missingCardTitle: "DNS-сервер не найден",
      missingDescription:
        "Вернитесь к таблице DNS-серверов и выберите корректную запись.",
      back: "Назад к DNS-серверам",
      description: "Этот сервер будет доступен в DNS-правилах и как fallback.",
      cardDescription:
        "Выберите тип DNS-сервера и необязательный detour outbound.",
      editCardTitle: "Изменить {{tag}}",
      fields: {
        tag: "Название",
        tagHint: "Короткое название сервера для использования в DNS-правилах.",
        type: "Тип DNS",
        typeHint:
          "Keenetic использует текущий встроенный DNS роутера. Plaintext DNS использует IP-адрес, введённый вручную.",
        typeOptions: {
          keenetic: "Keenetic DNS",
          static: "Plaintext DNS",
        },
        keeneticNotice: {
          description:
            "Для этого режима DNS-серверы нужно настроить в веб-интерфейсе Keenetic.",
          openLink: "Перейти к настройке",
          navigation:
            "Перейдите в Сетевые правила -> Интернет-фильтры -> Настройка DNS.",
          dotDohOnly:
            "Если там настроены DoT или DoH серверы, будут использоваться только они.",
        },
        address: "Адрес",
        addressPlaceholder: "1.1.1.1 или [2606:4700::1111]:53",
        addressHint:
          "IP-адрес сервера, напр. `1.1.1.1` или `[2606:4700::1111]:53`.",
        detour: "Делать запросы через Outbound",
        detourEmpty: "Не выбрано",
        detourPlaceholder: "Необязательный тег outbound",
        detourHint:
          "Необязательно: отправлять DNS-запросы к этому серверу через конкретный outbound (например, VPN).",
      },
      validation: {
        tagRequired: "Название обязательно.",
        tagUnique: "Название должно быть уникальным.",
        typeRequired: "Тип DNS обязателен.",
        addressRequired: "Адрес обязателен.",
        addressInvalid:
          "Адрес должен быть корректным IPv4/IPv6 значением с необязательным портом.",
      },
      actions: {
        create: "Создать DNS-сервер",
        save: "Сохранить DNS-сервер",
      },
    },
    routingRules: {
      title: "Правила маршрутизации",
      description:
        "Правила, определяющие, какой outbound обрабатывает подходящий трафик. Проверяются сверху вниз.",
      actions: {
        reorder: "Перетащите, чтобы изменить порядок",
        addRule: "Добавить правило маршрутизации",
        enableRule: "Включить правило",
        disableRule: "Выключить правило",
      },
      messages: {
        saved:
          "Правила маршрутизации сохранены в черновик. Примените новый конфиг, чтобы записать их.",
      },
      bulk: {
        selected: "Выбрано: {{count}}",
        enable: "Включить выбранные",
        disable: "Выключить выбранные",
        delete: "Удалить выбранные",
        confirmDelete:
          "Удалить {{count}} правил(о/а) маршрутизации? Изменение нельзя отменить здесь одним действием.",
      },
      empty: {
        title: "Правил маршрутизации пока нет",
        description:
          "Добавьте правило маршрутизации, чтобы направлять подходящий трафик в outbound.",
      },
      headers: {
        order: "Порядок",
        criteria: "Условие",
        outbound: "Outbound",
        runtime: "Состояние",
        actions: "Действия",
      },
      criteriaLabels: {
        lists: "Списки",
        proto: "Протокол",
        dscp: "DSCP",
        sourceIp: "Исходный IP",
        destinationIp: "IP назначения",
        sourcePort: "Исходный порт",
        destinationPort: "Порт назначения",
      },
    },
    routingRuleUpsert: {
      createTitle: "Создать правило маршрутизации",
      editTitle: "Изменить правило маршрутизации",
      description:
        "Это правило направляет подходящий трафик в указанный outbound.",
      cardDescription:
        "Выберите списки и outbound, затем при необходимости сузьте правило по протоколу, портам и адресам.",
      messages: {
        saved:
          "Правило маршрутизации сохранено в черновик. Примените новый конфиг, чтобы записать его.",
      },
      missing: {
        cardDescription: "Запрошенное правило маршрутизации не найдено.",
        cardTitle: "Правило не найдено",
        description:
          "Вернитесь к таблице правил маршрутизации и выберите корректную запись.",
        back: "Назад к правилам маршрутизации",
      },
      validation: {
        atLeastOneCondition:
          "Укажите хотя бы одно условие: список, DSCP, адрес источника/назначения или порт источника/назначения.",
        dscpRange: "DSCP должен быть целым числом от 1 до 63.",
        outboundRequired: "Тег outbound обязателен.",
      },
      actions: { create: "Создать правило", save: "Сохранить правило" },
      fields: {
        lists: "Списки",
        listsPlaceholderDescription:
          "Добавьте один или несколько настроенных списков для этого правила.",
        noListsSelected: "Списки не выбраны",
        listsHint: "Выберите, к каким спискам применяется это правило.",
        proto: "Протокол",
        any: "Любой",
        anyLower: "любой",
        protocol: "Протокол",
        protoHint:
          "Фильтр по протоколу (TCP, UDP и т.д.). Оставьте пустым для «любого».",
        dscp: "DSCP",
        dscpHint:
          "Фильтр по DSCP-метке пакета. Оставьте пустым для любого значения.",
        sourcePort: "Исходный порт",
        destinationPort: "Порт назначения",
        sourcePortHint:
          "Исходный порт(ы). Через запятую, диапазоны допустимы. Префикс `!` для отрицания.",
        destinationPortHint:
          "Порт(ы) назначения. Через запятую, диапазоны допустимы. Префикс `!` для отрицания.",
        sourceAddresses: "Исходные адреса",
        destinationAddresses: "Адреса назначения",
        sourceAddressHint:
          "Исходный IP/CIDR. Через запятую. Префикс `!` для отрицания.",
        destinationAddressHint:
          "IP/CIDR назначения. Через запятую. Префикс `!` для отрицания.",
        outbound: "Outbound",
        selectOutbound: "Выберите outbound",
        configuredOutbounds: "Настроенные outbounds",
        outboundHint: "Какой outbound должен обрабатывать подходящий трафик.",
      },
      placeholders: {
        dscp: "46",
        sourcePort: "80,443 или 10000-20000",
        destinationPort: "443 или !53,123",
        sourceAddresses: "192.168.1.10,10.0.0.0/8",
        destinationAddresses: "2001:db8::1 или !203.0.113.0/24",
      },
    },
    outbounds: {
      groups: {
        interfaces: "Туннели и интерфейсы",
        failover: "Failover-группы",
        system: "Системные выходы",
      },
      title: "Outbounds (выходы)",
      description: "Настроенные outbounds и группы urltest.",
      actions: { new: "Добавить outbound" },
      bulk: {
        selected: "Выбрано: {{count}}",
        delete: "Удалить выбранные",
        confirmDelete:
          "Удалить {{count}} outbound(ов)? Связи проверяются только при сохранении.",
      },
      deleteDialog: {
        title: "Удалить outbound?",
        description:
          "При подтверждении операции будут произведены следующие действия:",
        confirm: "Удалить",
        items: {
          outboundPrefix: "Outbound",
          outboundSuffix: "будет удалён.",
          dependentOutboundPrefix: "Зависимый urltest outbound",
          dependentOutboundSuffix: "будет удалён.",
          routingRule: "Правило маршрутизации #{{number}} будет удалено.",
          ruleDetail: "{{label}}: {{value}}",
          dnsDetour: 'DNS-сервер "{{server}}" будет изменён.',
          urltestGroupChanged:
            'Группа #{{group}} urltest outbound "{{outbound}}" будет изменена.',
          urltestGroupRemoved:
            'Группа #{{group}} urltest outbound "{{outbound}}" будет удалена.',
          groupOutbounds: "Outbounds",
        },
      },
      empty: {
        title: "Outbounds пока нет",
        description:
          "Добавьте outbound, чтобы начать строить поведение маршрутизации.",
      },
      headers: {
        tag: "Название",
        type: "Тип",
        summary: "Детали",
        runtime: "Состояние",
        actions: "Действия",
      },
      summary: {
        interface: "ifname={{value}}",
        gateway4: "gateway4={{value}}",
        gateway6: "gateway6={{value}}",
        table: "table={{value}}",
        urltest: "outbounds={{value}}",
      },
      messages: {
        missingReference:
          'Outbound "{{outbound}}" ссылается на отсутствующий тег "{{referenced}}".',
      },
    },
    outboundUpsert: {
      createTitle: "Создать outbound",
      editTitle: "Изменить outbound",
      editCardTitle: "Изменить {{tag}}",
      description:
        "Outbound может быть сетевым интерфейсом, таблицей маршрутизации или группой urltest, которая выбирает самый быстрый вариант.",
      cardDescription: "Настройте interface или urltest outbound.",
      missing: {
        cardDescription: "Запрошенный outbound не найден.",
        cardTitle: "Outbound не найден",
        description:
          "Вернитесь к таблице outbounds и выберите корректную запись.",
        back: "Назад к outbounds",
      },
      actions: { create: "Создать outbound", save: "Сохранить outbound" },
      common: {
        noExtraFields:
          "Для этого типа не нужны дополнительные поля, кроме тега outbound.",
      },
      fields: {
        tag: "Название",
        tagHint:
          "Уникальное название для этого outbound. Используется в правилах и группах.",
        type: "Тип",
        outboundTypes: "Типы outbound",
        typeOptions: {
          interface: "Интерфейс",
          table: "Таблица маршрутизации",
          urltest: "Автовыбор (urltest)",
          blackhole: "Blackhole",
          ignore: "Ignore",
        },
      },
      interface: {
        title: "Настройки интерфейса",
        description:
          "Укажите исходящий интерфейс и необязательные IPv4/IPv6 шлюзы для этого outbound.",
        interface: "Интерфейс",
        interfacePlaceholder: "Выберите или введите интерфейс",
        interfaceHint:
          "Имя исходящего интерфейса, напр. `tun0`, `eth0`, `wg0`.",
        gateway: "Шлюз (IPv4)",
        gatewayHint: "Необязательный IPv4-адрес шлюза для этого outbound.",
        gateway6: "Шлюз (IPv6)",
        gateway6Hint: "Необязательный IPv6-адрес шлюза для этого outbound.",
      },
      table: {
        title: "Настройки таблицы маршрутизации",
        description:
          "Привязать этот outbound к существующей таблице маршрутизации ядра.",
        field: "ID таблицы",
        hint: "ID таблицы маршрутизации ядра для этого outbound.",
      },
      blackhole: {
        title: "Поведение blackhole",
        description:
          "Outbounds типа blackhole намеренно отбрасывают весь подходящий трафик.",
      },
      ignore: {
        title: "Поведение ignore",
        description:
          "Outbounds типа ignore пропускают подходящий трафик без изменения policy-based routing.",
      },
      urltest: {
        groupsTitle: "Группы outbound (urltest)",
        groupsDescription:
          "Добавьте outbounds в группу. Самый быстрый outbound (по urltest-проверке) будет выбран автоматически.",
        groupTitle: "Группа {{index}}",
        groupDescription:
          "Приоритет {{index}} - группы с более высоким приоритетом предпочтительнее.",
        interfaceOutbounds: "Interface outbounds",
        addOutbound: "Добавить outbound",
        noInterfaceOutbounds: "Interface outbounds не найдены.",
        addInterfaceOutboundsFirst:
          "Сначала добавьте interface outbounds, чтобы у групп urltest были цели для выбора.",
        addGroup: "Добавить группу",
        probingTitle: "Проверки и повторы",
        probingDescription:
          "Настройте, как группа urltest проверяет кандидатов и повторяет неудачные проверки.",
        probeUrl: "URL проверки",
        probeUrlHint:
          "Сервис загружает этот URL с заданным интервалом, чтобы проверить доступность интерфейса и измерить задержку.",
        interval: "Интервал (мс)",
        intervalHint: "Как часто запрашивать Probe URL (в миллисекундах).",
        tolerance: "Допуск (мс)",
        toleranceHint:
          "Не переключать outbound, если разница задержки не превышает это значение. Предотвращает флаппинг.",
        retryAttempts: "Число повторов",
        retryAttemptsHint:
          "Дополнительные попытки проверки перед тем, как считать outbound неработающим.",
        retryInterval: "Интервал повтора (мс)",
        retryIntervalHint:
          "Задержка между повторами после неудачной проверки (в миллисекундах).",
      },
      circuitBreaker: {
        title: "Circuit breaker - ограничение проверок при устойчивых сбоях",
        description:
          "Предотвращает избыточные проверки, когда интерфейс или URL проверки устойчиво недоступен.",
        failures: "Ошибок до открытия",
        failuresHint:
          "Открыть circuit после такого числа последовательных сбоев.",
        successes: "Успехов до закрытия",
        successesHint: "Число успешных проверок для закрытия circuit.",
        timeout: "Таймаут открытия (мс)",
        timeoutHint:
          "Как долго circuit остаётся открытым до начала half-open проверок (в мс).",
        halfOpen: "Half-open проверки",
        halfOpenHint:
          "Количество попыток проверки в фазе half-open, прежде чем circuit полностью закроется или откроется снова.",
      },
      strictEnforcement: {
        label: "Переопределение kill-switch",
        hint: "Переопределяет глобальную настройку kill-switch для этого outbound.",
        default: "По умолчанию (как в глобальном конфиге)",
      },
      validation: {
        tagRequired: "Тег обязателен.",
        duplicateTag: 'Тег outbound "{{tag}}" уже существует.',
        missingReference:
          'Outbound "{{outbound}}" ссылается на отсутствующий тег "{{referenced}}".',
      },
    },
    dnsRules: {
      title: "DNS-правила",
      description:
        "Определяет, какой DNS-сервер используется для доменов из ваших списков.",
      actions: {
        add: "Добавить DNS-правило",
        enableRule: "Включить правило",
        disableRule: "Выключить правило",
      },
      bulk: {
        selected: "Выбрано: {{count}}",
        enable: "Включить выбранные",
        disable: "Выключить выбранные",
        delete: "Удалить выбранные",
        confirmDelete: "Удалить {{count}} DNS-правил(о/а)?",
      },
      messages: {
        saved:
          "Конфигурация DNS сохранена в черновик. Примените новый конфиг, чтобы записать её.",
      },
      validation: {
        invalidFallback:
          "Основные DNS-серверы должны ссылаться на существующие теги серверов.",
        invalidFallbackChange:
          "Нельзя изменить fallback, пока DNS-правила невалидны.",
        invalidResult:
          "Нельзя сохранить, потому что итоговые DNS-правила невалидны.",
      },
      fallback: {
        title: "Основные DNS-серверы",
        description:
          "Упорядоченный список DNS-серверов, которые dnsmasq использует, когда ни одно DNS-правило не подходит.",
        add: "Добавить основной DNS сервер",
        placeholderTitle: "Основные DNS-серверы не выбраны",
        placeholderDescription:
          "Добавьте один или несколько DNS-серверов. Их порядок сохраняется и используется в сгенерированном конфиге dnsmasq.",
        noneDefined: "На странице DNS-серверы не добавлено ни одного сервера.",
        noneAvailable: "Все DNS-серверы уже выбраны.",
      },
      empty: {
        title: "DNS-правил пока нет",
        description:
          "Правил пока нет - добавьте правило, чтобы направлять DNS-запросы по спискам через выбранный сервер.",
      },
      headers: {
        criteria: "Условие",
        serverTag: "DNS-сервер",
        allowDomainRebinding: "Разрешение rebind",
        actions: "Действия",
      },
      criteriaLabels: {
        lists: "Списки",
      },
      rebinding: {
        enabled: "Разрешён",
        disabled: "Запрещён",
      },
    },
    dnsRuleUpsert: {
      createTitle: "Создать DNS-правило",
      editTitle: "Изменить DNS-правило",
      description:
        "Это правило определяет, какой DNS-сервер использовать для доменов из конкретного списка.",
      cardDescription: "Укажите имена списков и DNS-сервер для этого правила.",
      messages: {
        saved:
          "DNS-правило сохранено в черновик. Примените новый конфиг, чтобы записать его.",
      },
      validation: {
        notFound: "Запрошенное DNS-правило не найдено.",
        fixErrors: "Исправьте ошибки валидации перед сохранением.",
        serverRequired: "Правило должно ссылаться на существующий DNS-сервер.",
        listsRequired: "Правило должно содержать хотя бы один список.",
        unknownLists: "Неизвестные списки: {{lists}}",
        duplicate: "Дублирующееся правило.",
      },
      missing: {
        cardDescription: "Запрошенное DNS-правило не найдено.",
        cardTitle: "DNS-правило не найдено",
        description: "Вернитесь к DNS-правилам и выберите корректную запись.",
        back: "Назад к DNS-правилам",
      },
      actions: { create: "Создать правило", save: "Сохранить правило" },
      fields: {
        serverTag: "DNS-сервер",
        selectServer: "Выберите DNS-сервер",
        dnsServers: "DNS-серверы",
        noServers: "На странице DNS-серверы не добавлено ни одного сервера.",
        listNames: "Списки доменов",
        allowDomainRebinding: "Разрешить DNS rebind для этих доменов",
        allowDomainRebindingHint:
          "Включайте только если вы точно знаете, что этот список доменов указывает на внутренние сервисы. Тогда ответы для подходящих доменов могут содержать внутренние/приватные IP-адреса (например, 192.168.0.0/16, 10.0.0.0/8 и другие диапазоны локальной сети).",
        listPlaceholderDescription:
          "Выберите списки для этого правила. Совпадающие домены будут использовать этот DNS-сервер.",
        noListsSelected: "Списки не выбраны",
        noLists:
          "Не найдено ни одного списка. Пожалуйста, сначала создайте его на странице Списки.",
      },
    },
    lists: {
      title: "Списки",
      description:
        "Группы доменов и IP-адресов для использования в правилах трафика и DNS.",
      actions: {
        new: "Добавить список",
        update: "Обновить",
        updateAll: "Обновить все",
      },
      empty: {
        title: "Списков пока нет",
        description:
          "Создайте первый список, чтобы использовать его в правилах маршрутизации и DNS.",
      },
      headers: {
        name: "Имя",
        type: "Тип",
        stats: "Записи",
        rules: "Исп. в правилах",
        actions: "Действия",
      },
      delete: {
        confirm: 'Удалить список "{{name}}"?',
        confirmWithReferences:
          'Удалить список "{{name}}" и убрать его ссылки из правил маршрутизации и DNS?',
      },
      deleteDialog: {
        title: "Удалить списки?",
        description:
          "При подтверждении операции будут произведены следующие действия:",
        confirm: "Удалить",
        items: {
          listPrefix: "Список",
          listSuffix: "будет удалён.",
          routeRuleRemoved: "Правило маршрутизации #{{number}} будет удалено.",
          routeRuleUpdated: "Правило маршрутизации #{{number}} будет изменено.",
          dnsRuleRemoved: "DNS-правило #{{number}} будет удалено.",
          dnsRuleUpdated: "DNS-правило #{{number}} будет изменено.",
        },
      },
      bulk: {
        selected: "Выбрано: {{count}}",
        refreshSelected: "Обновить выбранные (URL)",
        deleteSelected: "Удалить выбранные списки",
        confirmDeleteSimple: "Удалить списки: {{names}}?",
        confirmDeleteWithRefs:
          "Удалить списки: {{names}} и при необходимости убрать ссылки из правил маршрутизации и DNS?",
        noUrlBacked:
          "Ни один выбранный список не основан на URL (обновлять нечего).",
      },
      location: {
        inline: "Встроенный",
      },
      refresh: {
        draftBlocked:
          "Примените черновик конфигурации перед обновлением списков.",
        updateDisabled: "Примените черновик перед обновлением",
      },
      rule: {
        configured: "Настроен",
      },
      messages: {
        refreshedOne: "Обновление списка завершено.",
        refreshedAll: "Обновление списков завершено.",
        refreshFailedOne:
          'Список "{{names}}" не удалось обновить. Подробности смотрите в логах.',
        refreshFailedMany:
          "Не удалось обновить {{count}} списков: {{names}}. Подробности смотрите в логах.",
        refreshFailedMore: "ещё {{count}}",
      },
      lastUpdated: "Последнее обновление: {{value}}",
      neverUpdated: "Ещё не обновлялся",
      noStats: "-",
      source: {
        url: "URL",
        file: "Файл",
        domains: "Домены",
        ip_cidrs: "IP CIDR",
        empty: "Пусто",
      },
    },
    listUpsert: {
      templates: {
        button: "Выбрать из готовых",
        title: "Готовые списки",
        description: "Подборка правил sing-box: выберите нужный сервис, и ссылка подставится в поле URL.",
        search: "Поиск по названию или адресу",
        add: "Выбрать",
        empty: "Ничего не найдено",
        categories: {
          ai: "Нейросети",
          social: "Соцсети и мессенджеры",
          media: "Медиа и стриминги",
          gaming: "Игры",
          developer: "Разработка и работа",
          cloud: "Облака и платформы",
          block: "Блокировки",
          other: "Прочее",
        },
      },
      createTitle: "Создать список",
      editTitle: "Изменить список",
      editCardTitle: "Изменить {{name}}",
      fallbackName: "список",
      description:
        "Список может содержать домены и IP, введённые вручную, загруженные по URL или из файла.",
      cardDescription:
        "Проверьте источник списка, TTL и содержимое перед сохранением.",
      messages: {
        created:
          "Список сохранён в черновик. Примените новый конфиг, чтобы записать его.",
        updated:
          "Изменения списка сохранены в черновик. Примените новый конфиг, чтобы записать их.",
      },
      missing: {
        cardDescription: "Запрошенный список не найден.",
        cardTitle: "Список не найден",
        description:
          "Вернитесь к таблице списков и выберите корректную запись.",
        back: "Назад к спискам",
      },
      actions: {
        saving: "Сохранение...",
        create: "Создать список",
        save: "Сохранить список",
      },
      common: {
        title: "Параметры списка",
        description: "Задайте идентификатор списка перед выбором источника.",
      },
      sourceSwitcher: {
        title: "Тип источника",
        description:
          "Выберите источник для редактирования. Старые списки с несколькими сохранёнными источниками останутся видимыми, пока вы не переключитесь.",
        confirmChange:
          "Переключить тип источника и очистить заполненные сейчас поля?",
      },
      sourceGroups: {
        url: {
          button: "URL",
          title: "Удалённый URL",
          description:
            "Загружает записи списка с удалённой точки по HTTP или HTTPS и задаёт время жизни кэша для разрешённых IP.",
        },
        file: {
          button: "Файл на устройстве",
          title: "Локальный файл",
          description: "Читает записи списка из файла, доступного на роутере.",
        },
        inline: {
          button: "Домены / IP",
          title: "Домены / IP",
          description: "Позволяет указать домены и IP-адреса прямо в конфиге.",
        },
      },
      dnsRule: {
        title: "DNS-сервер для этого списка",
        description: "Домены из списка будут разрешаться через выбранный DNS-сервер. Без выбора список использует основные серверы.",
        none: "Не задан",
      },
      quickSetup: {
        title: "Быстрая настройка правил",
        description:
          "Необязательно создайте связанные правила одновременно со списком. Все изменения сохраняются одной операцией.",
        createRouteRule: "Создать правило маршрутизации для этого списка",
        selectOutbound: "Выберите тоннель или другой outbound",
        createDnsRule: "Создать DNS-правило для этого списка",
        selectDnsServer: "Выберите DNS-сервер",
        noDnsServers:
          "Сначала создайте DNS-сервер — после этого его можно будет выбрать здесь.",
        manualHint:
          "Оставьте флажки выключенными, чтобы настроить правила вручную после создания списка.",
        routeRequired: "Выберите outbound для правила маршрутизации.",
        dnsRequired: "Выберите DNS-сервер для DNS-правила.",
      },
      fields: {
        name: "Имя",
        nameHint: "Стабильный идентификатор для использования в правилах.",
        ttlMs: "Время жизни IP-кэша (мс)",
        ttlMsHint:
          "Как долго хранить разрешённые IP в ipset. `0` = без таймаута.",
        detour: "Делать запросы через Outbound",
        detourEmpty: "Не выбрано",
        detourPlaceholder: "Необязательный тег outbound",
        detourHint:
          "Необязательный outbound для загрузки этого списка по удалённому URL.",
        url: "Удалённый URL",
        urlHint:
          "Необязательно: URL для загрузки записей. Объединяется с остальным содержимым.",
        file: "Абсолютный путь к файлу",
        fileHint:
          "Необязательно: путь к файлу на устройстве. Объединяется с другими источниками.",
        domains: "Домены",
        domainsHint:
          "Домены, по одному в строке. `example.com` автоматически включает все поддомены.",
        ipCidrs: "IP CIDR",
        ipCidrsHint:
          "IP-адреса или диапазоны CIDR, по одному в строке. Напр. `93.184.216.34`, `10.0.0.0/8`.",
      },
      validation: {
        nameRequired: "Имя обязательно.",
        duplicateName: "Список с таким именем уже существует.",
        invalidTtl: "TTL должен быть неотрицательным целым числом.",
      },
    },
  },
} as const

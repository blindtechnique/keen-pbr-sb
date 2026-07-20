export const enTranslation = {
  nfqws: {
    description:
      "Manage nfqws2, strategies, configuration, lists, Lua scripts and logs.",
    refresh: "Refresh",
    service: "nfqws2 service",
    version: "Installed version: {{version}}",
    running: "Running",
    stopped: "Stopped",
    start: "Start",
    stop: "Stop",
    restart: "Restart",
    reload: "Reload configuration",
    upgrade: "Upgrade package",
    operationResult: "nfqws2 operation result",
    operationCompleted: "The operation completed successfully.",
    closeResult: "Close message",
    tabs: {
      settings: "Settings",
      strategies: "Strategies",
      lists: "Lists",
      lua: "Lua scripts",
      logs: "Logs",
      check: "Website check",
    },
    notInstalled: {
      title: "nfqws2 is not installed",
      description:
        "This page remains available, but management requires the official nfqws2-keenetic package.",
      ourInstaller: "Using the keen-pbr-sb installer (recommended)",
      original: "Using the original nfqws2 repository",
    },
    settingsTitle: "nfqws2 settings",
    settingsDescription:
      "The form updates /opt/etc/nfqws2/nfqws2.conf while preserving other configuration lines.",
    strategiesTitle: "Strategies",
    strategiesDescription:
      "Select a bundled strategy, edit it, save a user version or apply it to nfqws2.",
    builtin: "bundled",
    activeStrategy: "active",
    activeStrategyLabel: "Currently applied:",
    activeStrategyCustom: "manually modified configuration",
    selectedForEditing: "Selected for editing: {{name}}",
    strategyAppliedAndRestarted:
      "The strategy was applied and the nfqws2 service restarted.",
    addStrategy: "New strategy",
    strategyName: "New strategy name",
    applyStrategy: "Apply",
    saveStrategy: "Save",
    confirmDelete: "Delete the selected file or strategy?",
    fileName: "New filename without extension",
    newFile: "New file",
    save: "Save",
    saved: "Changes saved",
    clearLog: "Clear log",
    confirmClearLog: "Clear the selected nfqws2 log?",
    logCleared: "Log cleared",
    configMissing: "nfqws2.conf was not found.",
    checkTitle: "Website availability check",
    checkDescription:
      "Checks the HTTP response from the router, equivalent to the original nfqws-web check.",
    check: "Check",
    reachable: "The website returned a readable response.",
    unreachable: "The website is unavailable or returned no readable response.",
  },
  configTransfer: {
    export: "Export",
    import: "Import",
    invalidFormat: "The file is not a compatible keen-pbr-sb export.",
    replaceLists:
      "Replace all existing lists? Choose Cancel to merge them instead.",
    replaceRules:
      "Replace all routing rules? Choose Cancel to append imported rules instead.",
    mapOutbound:
      "Outbound “{{missing}}” does not exist. Select one of: {{available}}",
    outboundRequired:
      "Every imported rule must be mapped to an existing outbound.",
  },
  auth: {
    title: "Sign in to keen-pbr-sb",
    description: "Authenticate to open routing management.",
    username: "Username",
    password: "Password",
    signIn: "Sign in",
    signingIn: "Signing in…",
    signOut: "Sign out",
    invalidCredentials: "Invalid username or password.",
    unavailable: "The authentication service is unavailable.",
    credentialsHint:
      "Credentials are configured by the keen-pbr-sb installer. This is a separate local account; see README for details.",
  },
  common: {
    language: "Language",
    theme: "Theme",
    enabled: "Enabled",
    disabled: "Disabled",
    close: "Close",
    cancel: "Cancel",
    saving: "Saving…",
    copy: "Copy",
    copied: "Copied",
    clipboardUnavailable: "Clipboard unavailable",
    edit: "Edit",
    delete: "Delete",
    moveUp: "Move up",
    moveDown: "Move down",
    unableToLoadData: "Unable to load data",
    loadErrorDescription:
      "We can't load data right now. Try refreshing the page.",
    noneShort: "-",
    multiSelectList: {
      addItem: "Add item",
      emptyMessage: "No items found.",
      availableItems: "Available items",
      noItemsSelected: "No items selected",
      addFirstItem: "Add your first item to start building this list.",
      removeItem: "Remove {{item}}",
    },
    listUsage: {
      usedElsewhere: "Also in: {{summary}}",
    },
    interfacePicker: {
      open: "Open interface picker",
      empty: "No interfaces found.",
      notExists: "(not exists)",
      notFound: "Interface does not exist.",
    },
    validation: {
      tagNamePattern:
        "Can only contain a-z, 0-9 and underscores. Max 24 characters, must start with a letter.",
    },
    selection: {
      selectAll: "Select all visible rows",
      selectRow: "Select {{rowLabel}}",
    },
  },
  runtime: {
    healthy: "Healthy",
    notHealthy: "Not healthy",
    activeOutbound: "Active outbound {{value}}",
    activeInterface: "Active {{value}}",
    outboundStatus: {
      healthy: "Healthy",
      degraded: "Degraded",
      unavailable: "Unavailable",
      unknown: "Unknown",
    },
    interfaceStatus: {
      active: "Active",
      backup: "Backup",
      degraded: "Degraded",
      unavailable: "Unavailable",
      unknown: "Unknown",
    },
    fallback: {
      table: "Routing table {{value}}",
      blackhole: "Block all incoming traffic",
    },
  },
  language: {
    selectorAria: "Language selector",
    english: "English",
    russian: "Russian",
  },
  theme: {
    selectorAria: "Theme selector",
    useSystem: "Use system setting",
    light: "Light",
    dark: "Dark",
  },
  nav: {
    groups: {
      general: "General",
      internet: "Internet",
      networkRules: "Traffic Rules",
    },
    items: {
      systemMonitor: "Dashboard",
      catalog: "List catalogue",
      settings: "Settings",
      outbounds: "Outbounds",
      transports: "Transports",
      connections: "Connections",
      dnsServers: "DNS Servers",
      lists: "Lists",
      routingRules: "Routing rules",
      dnsRules: "DNS Rules",
    },
  },
  notifications: {
    clear: "Clear",
    title: "Notifications",
    empty: "Nothing to report",
    updateAvailable: "Version {{version}} is available",
  },
  connections: {
    age: {
      live: "Active",
      now: "just now",
      seconds: "{{count}}s ago",
      minutes: "{{count}}m ago",
      hours: "{{count}}h ago",
    },
    deviceCount: "{{count}} devices",
    routeDirect: "Direct",
    empty: "No connections",
    title: "Connections",
    description:
      "Active connections and up to 1,500 recent records. DNS traffic observed by keen-pbr adds the last known domain next to the exact IP. Data refreshes every 3 seconds.",
    filter: "Filter by device, domain, address, state, or route",
    activeOnly: "Active only",
    sort: "Sort",
    sortRecent: "Newest first",
    sortSource: "By device",
    sortDestination: "By destination",
    sortRoute: "By route",
    state: "State",
    device: "Device / source",
    destination: "Destination",
    protocol: "Protocol",
    route: "Route",
  },
  transports: {
    latencyValue: "{{value}} ms",
    latencyAge: "{{seconds}}s ago",
    latencyRefresh: "Measure now",
    dnsDetour: "DNS through this tunnel",
    singBoxMissing: {
      title: "sing-box is not installed",
      description:
        "VLESS, VMess, Trojan, Shadowsocks and other managed proxy transports require sing-box. Run the keen-pbr-sb installer over SSH and select the tested version.",
    },
    title: "Transports",
    description:
      "Native and managed tunnel interfaces available to keen-pbr outbounds.",
    refresh: "Refresh",
    add: "Add transport",
    unavailable: "Transport manager unavailable",
    empty: "No transports configured.",
    interface: "Interface",
    server: "Server",
    loopProtection: {
      action: "Exclude server from tunnel",
      confirm:
        "Add {{server}} to the first pass-through rule? This creates the transport_servers list, an ignore outbound named transport_bypass, and a highest-priority routing rule.",
      saved: "Routing-loop protection was added",
      tagConflict:
        "Tag {{tag}} is already used by another outbound type. Rename it and try again.",
    },
    pid: "PID",
    updatedAt: "Updated",
    autoRecovery: "Auto recovery",
    enabled: "Enabled",
    paused: "Paused by user",
    retryCount: "Recovery attempts",
    nextRetryAt: "Next retry",
    start: "Start",
    stop: "Stop",
    restart: "Restart",
    latency: "Latency",
    latencyUnavailable: "not measured",
    started: "Transport start requested",
    stopped: "Transport stop requested",
    restarted: "Transport restart requested",
    nativeManagedExternally:
      "This native interface is managed by KeeneticOS or another service.",
    deleteTitle: "Delete transport?",
    deleteDescription:
      "The managed process will be stopped and its definition removed.",
    configMessages: {
      create: "Transport created",
      update: "Transport updated",
      delete: "Transport deleted",
    },
    form: {
      createOutbound: "Create an outbound right away",
      createOutboundHint: "Adds an interface outbound with the same tag so the transport can be picked in routing rules immediately.",
      outboundExists: "An outbound tagged {{tag}} already exists",
      createTitle: "Add transport",
      editTitle: "Edit transport",
      description:
        "Expose a native interface or a scoped proxy TUN to keen-pbr.",
      tag: "Tag",
      tagHint:
        "1–24 characters: start with a lowercase Latin letter, then use only a–z, 0–9 and underscore. Example: my_transport.",
      type: "Type",
      native: "Native interface",
      singBox: "sing-box connection",
      singBoxLegacy: "sing-box (legacy VLESS configuration)",
      interface: "Interface name",
      autoStart: "Start automatically",
      shareLink: "Connection link",
      shareLinkHint:
        "Supports VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC, AnyTLS, SOCKS and HTTP proxy links.",
      outboundJson: "sing-box outbound JSON",
      outboundJsonHint:
        "Advanced mode for any outbound type supported by the installed sing-box version. The tag is assigned automatically.",
      keepConnection: "Leave blank to keep the saved connection",
      server: "Server",
      port: "Port",
      uuid: "UUID",
      serverName: "REALITY server name",
      publicKey: "REALITY public key",
      shortId: "REALITY short ID",
      fingerprint: "uTLS fingerprint",
      mtu: "MTU",
      bootstrapDns: "Bootstrap DNS",
      tunAddress: "TUN address (optional)",
      tunAddressPlaceholder: "Automatic dedicated /30 subnet",
      tunAddressHint:
        "Leave blank to derive a stable address from 172.19.0.0/16 using the tag. For a manual override, enter a usable /30 host such as 10.77.0.1/30.",
      bootstrapDnsHint:
        "DNS server IP addresses, one per line. They resolve the VPN server before the tunnel starts; an optional port is supported.",
      keepSecret: "Leave blank to keep the saved UUID",
      saving: "Saving…",
      save: "Save",
    },
    routing: {
      title: "A transport is not a route yet",
      description:
        "First bind the transport interface to an Interface outbound. For automatic switching, create a URLTest outbound and add two or more interface outbounds to its groups.",
      createOutbound: "Create interface outbound",
      createFailover: "Create failover (URLTest)",
      bindOutbound: "Create outbound for this interface",
    },
    states: {
      connected: "Connected",
      down: "Down",
      starting: "Starting",
      up: "Up",
      degraded: "Degraded",
    },
  },
  brand: {
    logoAlt: "keen-pbr-sb logo",
    version: "Version {{version}}",
    tagline: "Get packets sorted",
    openMenu: "Open menu",
  },
  warning: {
    draftChanged: "Configuration was changed. Save it to disk to apply it.",
    actions: {
      applying: "Applying...",
      apply: "Apply",
      applyingAndRestarting: "Applying & Restarting...",
      applyAndRestart: "Apply & Restart",
      restarting: "Restarting...",
      restart: "Restart",
    },
    compact: {
      keenRestartRequired: "Pending changes",
      keenRestartRequiredDescription:
        "New settings found. Apply to restart keen-pbr.",
      keenAndDnsmasqRestartRequired: "Out of sync",
      keenAndDnsmasqRestartRequiredDescription:
        "Apply changes to sync keen-pbr and dnsmasq.",
      dnsmasqRestartRequired: "DNS-server config is outdated",
      dnsmasqRestartRequiredDescription:
        "dnsmasq needs a restart to update its resolver config.",
      dnsmasqRestarting: "Restarting dnsmasq...",
      dnsmasqRestartingDescription: "dnsmasq is restarting. Please wait.",
      dnsmasqUnavailable: "dnsmasq probe failed",
      dnsmasqUnavailableDescription:
        "keen-pbr could not query the dnsmasq health TXT record. Try Apply & Restart if this persists.",
      staleAfterTimeout:
        "dnsmasq last reloaded at {{actualTs}}. Restart routing runtime if this stays stale.",
    },
    full: {
      unsavedTitle: "Configuration is unsaved",
      staleTitle: "dnsmasq is using a stale resolver config",
      staleDescription:
        "The expected resolver hash ({{expected}}…) doesn't match dnsmasq's active hash ({{actual}}…).",
    },
  },
  overview: {
    router: {
      title: "Router",
      unavailable: "Router details are unavailable: the firmware is not answering service requests.",
      cpu: "CPU",
      memory: "Memory",
      memoryValue: "{{used}} MB / {{total}} MB ({{percent}}%)",
      memoryTotalOnly: "{{total}} MB",
      wifi: "Wi-Fi",
      wan: "WAN address",
      clients: "Clients",
      clientsValue: "{{active}} active / {{total}} total",
      firmware: "Firmware",
      uptime: "Uptime",
      uptimeValue: "{{days}}d {{hours}}h {{minutes}}m",
      loadAverage: "Load average",
    },
    services: {
      summary: {
        keenPbr: "Routes traffic into the right tunnel by list",
        singbox: "Runs the VLESS, Trojan and similar tunnels",
        nfqws: "Circumvents blocking for traffic that stays direct",
      },
      version: "Version {{version}}, build {{build}}",
      unknown: "State unknown",
      restart: "Restart",
      restartRequested: "Restart requested",
      restartFailed: "Restart failed",
      title: "Services",
      singbox: "sing-box",
      nfqws: "nfqws2",
      transportsRunning: "{{running}} of {{total}} running",
      noTransports: "No transports configured",
      notInstalled: "Not installed",
      running: "Service is running",
      stopped: "Service is stopped",
      badgeUp: "Running",
      badgeDown: "Stopped",
      badgeAbsent: "None",
    },
    pageDescription:
      "Overview of routing runtime, config state, and active outbounds",
    runtime: {
      title: "Routing runtime",
      description: "Control policy-based routing.",
      loadError: "Failed to load routing runtime state.",
      version: "Version",
      router: "Router",
      status: "Routing status",
      dnsmasqHealthy: "dnsmasq healthy",
      dnsmasqWaiting: "dnsmasq reloading",
      dnsmasqStale: "dnsmasq restart required",
      dnsmasqUnavailable: "dnsmasq probe failed",
      dnsmasqUnknown: "dnsmasq status unknown",
      actions: {
        start: "Start",
        stop: "Stop",
        restart: "Restart",
      },
    },
    outbounds: {
      members: "{{count}} in group",
      kind: {
        failover: "Failover",
        table: "Table",
        blackhole: "Blackhole",
        ignore: "Pass-through",
        interface: "Interface",
      },
      status: {
        healthy: "Healthy",
        unavailable: "Not responding",
        degraded: "Down",
        unknown: "Unknown",
        misconfigured: "Misconfigured",
      },
      member: {
        active: "Active",
        backup: "Backup",
        degraded: "Not responding",
        unavailable: "Unavailable",
        unknown: "Unknown",
      },
      title: "Outbounds health",
      loadError: "Unable to load outbound health.",
      emptyTitle: "No outbounds configured",
      emptyDescription: "Add outbounds to see health checks.",
      inUse: "In use",
      urltestTitle: "urltest",
      headers: {
        tag: "Tag",
        destination: "Destination",
        status: "Status",
      },
      destination: {
        interface: "Interface {{name}}",
        interfaceWithGateway: "Interface {{name}} (gw: {{gateway}})",
        table: "Table {{value}}",
        outbound: "Outbound {{name}}",
      },
    },
    routing: {
      title: "Diagnostics",
      loadError: "Unable to load routing checks.",
      emptyTitle: "No routing checks reported yet",
      emptyDescription:
        "Routing checks will appear after the next apply or runtime restart.",
      showHealthyEntries: "Show healthy entries too",
      allHealthyTitle: "Everything is good",
      allHealthyDescription: "No failing routing health entries right now.",
      noChecksTitle: "No checks reported",
      noChecksDescription: "Routing health has no entries to display.",
      sections: {
        firewall: "Firewall",
        routes: "Routes",
        policies: "Policies",
      },
      chain: "chain",
      prerouting: "prerouting",
      defaultRoute: "default",
      ipv4: "IPv4",
      ipv6: "IPv6",
      yes: "yes",
      no: "no",
      tableLabel: "table {{value}}",
      priorityLabel: "priority {{value}}",
      fwmarkLabel: "fwmark {{value}}",
      fwmarkExpectedActual: "expected {{expected}}, got {{actual}}",
      actualLabel: "actual {{value}}",
      routeTypeFallback: "route",
      routeVia: "via {{value}}",
      routeGateway: "gw {{value}}",
      routeMetric: "metric {{value}}",
      issues: {
        tableMissing: "table missing",
        defaultRouteMissing: "default route missing",
        interfaceMismatch: "interface mismatch",
        gatewayMismatch: "gateway mismatch",
      },
    },
    diagnosticsDownload: {
      button: "Download diagnostics file",
      modal: {
        title: "Warning: sensitive data",
        description: "The diagnostics file includes:",
        items: {
          config: "Your full configuration file (including the lists in use)",
          serviceHealth: "Service health",
          routingHealth: "Routing health",
          outbounds: "Outbounds status",
          names: "Names of lists, outbounds, and interfaces",
        },
        trustWarning: "Please share this file only with people you trust.",
        hideListsOption: "Hide list contents and list URLs",
        downloadAction: "Download diagnostics file",
      },
    },
    dnsCheck: {
      card: {
        title: "DNS check",
        description:
          "Verifies that DNS resolution through keen-pbr is working correctly from this browser or another device.",
        disabledDescription:
          "Enable `dns.dns_test_server` option in the config file to run the DNS self-check.",
        configuredServers: "Configured DNS servers",
        noServers:
          "No upstream DNS servers are configured on the DNS Servers page.",
        via: "via {{detour}}",
        checking: "Checking...",
        runAgain: "Run again",
        testFromPc: "Test from another device",
      },
      modal: {
        title: "Test DNS from another device",
        description:
          "Run the generated `nslookup` command on your PC or phone while this dialog stays open.",
        copyCommand: "Copy and run this command:",
        warning:
          "The DNS test query has not arrived yet. Make sure the device is using your router DNS and try the command again.",
        copyAria: "Copy command",
      },
      status: {
        disabled: "Built-in DNS probe is disabled in config.",
        browserSuccess: "DNS request from the browser reached dnsmasq.",
        manualProbeSuccess: "DNS request from the device reached dnsmasq.",
        browserProbeFail:
          "Browser request completed, but the DNS probe did not see the lookup.",
        sseUnavailable:
          "The live DNS event stream is unavailable, so the check could not start.",
        browserFail:
          "Browser request ran, but the DNS lookup was not observed.",
        sseFail: "Live DNS event stream is not connected.",
        browserChecking: "Checking browser DNS path...",
        browserUnknown: "Browser DNS status is not known yet.",
        manualSuccess: "DNS request from the device reached dnsmasq.",
        manualWaiting: "Waiting for your manual nslookup command...",
        manualIncomplete: "Manual device test has not completed yet.",
      },
    },
    routingTest: {
      title: "Where does this traffic go?",
      placeholder: "e.g. google.com or 1.2.3.4",
      submit: "Check route",
      invalidTarget: "Please enter a valid domain or IP.",
      requestFailed: "Routing test failed. Please try again.",
      emptyTitle: "No route matched",
      emptyDescription: "Try another domain or IP address.",
    },
    routingDiagnostics: {
      noMatchingRule: "No matching routing rule for the target lists.",
      hostLabel: 'Host "{{target}}"',
      inRuleLists: "In rule domain/IP lists?",
      showAllRules: "Show all rules",
      listMatch: "{{list}}: {{via}}",
      noConditions: "No extra conditions",
      conditions: {
        lists: "Lists",
        proto: "Protocol",
        sourceIp: "Source IP",
        destinationIp: "Destination IP",
        sourcePort: "Source port",
        destinationPort: "Destination port",
      },
    },
    routingLegend: {
      title: "Legend",
      inLists: "In domain/IP lists",
      notInLists: "Not in domain/IP lists",
      inIpsetAndLists: "In IPSet and in lists",
      notInIpsetAndNotInLists: "Not in IPSet and not in lists",
      inIpsetButShouldNotBe: "In IPSet but should not be",
      notInIpsetButShouldBe: "Not in IPSet but should be",
    },
  },
  pages: {
    catalog: {
      title: "List catalogue",
      description:
        "Ready-made sets of domains and rules. Pick the ones you want and say where their traffic should go.",
      source: "Source:",
      updatedAt: "updated {{date}}",
      count: "{{count}} lists",
      downloadVia: "Download via",
      directly: "Directly",
      checkNow: "Check now",
      refreshed: "Catalogue updated",
      refreshFailed:
        "Could not refresh; showing the previous catalogue. Try downloading through a tunnel.",
      searchPlaceholder: "Search by name",
      empty: "Nothing found",
      ruleSet: "rule set",
      domains: "{{count}} domains",
      actionTunnel: "tunnel",
      actionBlock: "block",
      alreadyAdded: "already added",
      selected: "Selected: {{count}}",
      routeTo: "Route to",
      add: "Add",
      added: "Lists added: {{count}}",
      categories: {
        all: "All",
        ai: "AI",
        social: "Social",
        media: "Media",
        developer: "Development",
        cloud: "Cloud",
        gaming: "Gaming",
        block: "Blocking",
      },
    },
    settings: {
      remoteAccess: {
        title: "Access from outside",
        description: "Reach the web interface from the internet, not just from the home network.",
        enabled: "Allow access from the internet",
        port: "External port",
        portHint: "The port the panel answers on from outside. Pick something non-obvious.",
        warning:
          "The panel becomes reachable by anyone who knows the address and port, with only the password protecting it. Use this only if you accept that risk.",
        loginDisabled:
          "Turn on login first. Without it the panel would sit on the internet with no password at all.",
        listenLoopback:
          "The panel listens on {{listen}}, an address that only accepts connections from the router itself, so it cannot be published. Set api.listen to 0.0.0.0:12121 in config.json and restart the service.",
        save: "Save",
        saved: "Access settings saved",
      },
      logging: {
        title: "Log",
        description: "What keen-pbr-sb records about its own work.",
        enabled: "Write the log to a file",
        level: "Verbosity",
        levelHint:
          "Normal is enough day to day. The detailed levels are for investigating a problem and grow the file noticeably.",
        pathHint:
          "File: /opt/var/log/keen-pbr.log. A new one starts at one megabyte and the previous is kept alongside.",
        levels: {
          error: "Errors only",
          warn: "Errors and warnings",
          info: "Normal",
          verbose: "Detailed",
          debug: "Debug",
        },
        save: "Save",
        saved: "Logging settings saved",
      },
      auth: {
        title: "Web interface login",
        description: "How access to keen-pbr-sb is verified.",
        enabled: "Require sign-in",
        provider: "Verification method",
        providerRouter: "Router account",
        providerLocal: "Separate keen-pbr-sb password",
        providerRouterHint: "The Keenetic firmware checks the credentials; keen-pbr-sb never stores the password.",
        providerLocalHint: "Login and password are stored in auth.json on the router.",
        endpoint: "Router web interface address",
        username: "Username",
        password: "Password",
        verifyHint: "Enter the router credentials: they are verified before saving so you cannot lock yourself out.",
        localStoreHint: "Set the login and password you will use for keen-pbr-sb.",
        save: "Save login method",
        saved: "Login settings saved, sign in again",
      },
      title: "Settings",
      description:
        "Global defaults that apply to all your outbounds and rules.",
      saved: "Settings staged. Apply new config to persist them.",
      general: {
        title: "General",
        description: "Default behavior for all outbounds.",
        strictEnforcementLabel:
          "Block traffic when outbound drops (kill-switch)",
        strictEnforcementHint:
          "If a VPN or interface goes offline, traffic matching its rules is blocked instead of falling back to the main routing table. Can be overridden per outbound.",
        skipMarkedPacketsLabel: "Skip packets that are already marked",
        skipMarkedPacketsHint:
          "Ignore packets that already have a fwmark set by other firewall rules so policy routing does not process them again.",
        ipv6EnabledLabel: "Enable IPv6 support",
        ipv6EnabledHint:
          "Install IPv6 firewall sets and emit IPv6 dnsmasq targets. Disable this on older firmware without IPv6 netfilter support.",
        clientDnsEnforcementLabel: "Force clients to use router DNS",
        clientDnsEnforcementHint:
          "Transparently redirect plain DNS (port 53) from LAN clients to the router's resolver and block DNS-over-TLS (port 853), so browser Secure DNS cannot bypass domain-based routing. DNS-over-HTTPS on port 443 cannot be blocked this way; disable Secure DNS in browsers for full coverage.",
        inboundInterfacesLabel: "Inbound interfaces",
        inboundInterfacesHint:
          "Only packets arriving on the selected interfaces will be processed by policy routing. Leave this empty to match traffic from any interface.",
        inboundInterfacesAddAction: "Add interface",
        inboundInterfacesLoading: "Loading interfaces...",
        inboundInterfacesNoAvailable: "No more interfaces available.",
        inboundInterfacesEmptyTitle: "No inbound interfaces selected",
        inboundInterfacesEmptyDescription:
          "Add interfaces here if you want policy routing to apply only to specific ingress interfaces.",
        inboundInterfacesLoadError:
          "Live interface inventory is temporarily unavailable. Saved selections are still editable.",
        inboundInterfacesStatusUp: "UP",
        inboundInterfacesStatusDown: "DOWN",
        inboundInterfacesStatusLoading: "Loading",
        inboundInterfacesStatusMissing: "Missing",
        inboundInterfacesMissingDetail:
          "This interface is saved in config but is not present in the current live interface inventory.",
      },
      autoupdate: {
        scheduleHint: "How often to check the remote lists for updates.",
        schedule: {
          hourly: "Every hour",
          daily: "Every day",
          weekly: "Every week",
          monthly: "Every month",
          custom: "Custom schedule (cron)",
          atHour: "at {{hour}}:00",
          dayOfMonth: "on day {{day}}",
          weekdays: {
            sunday: "On Sundays",
            monday: "On Mondays",
            tuesday: "On Tuesdays",
            wednesday: "On Wednesdays",
            thursday: "On Thursdays",
            friday: "On Fridays",
            saturday: "On Saturdays",
          },
        },
        title: "Lists autoupdate",
        description: "Keep your remote lists up to date automatically.",
        enabledLabel: "Enable lists autoupdate",
        enabledHint:
          "Automatically download the latest version of your remote lists and update routing when they change.",
        cronLabel: "Refresh schedule",
        cronHintPrefix: "How often to check for updates. Uses cron format. Use",
        cronHintSuffix: "for help.",
        openInGuru: "Open in Crontab Guru",
      },
      softwareUpdate: {
        title: "keen-pbr-sb update",
        description:
          "Checks the latest published Release, verifies SHA256SUMS, and installs the IPK while preserving configuration, transports, and the web account.",
        current: "Installed",
        latest: "Latest release",
        check: "Check for updates",
        install: "Install update",
        running:
          "The update is running. The web UI may be unavailable for a few seconds and will reconnect automatically.",
        upToDate: "The latest published version is installed.",
        newerThanPublished:
          "The installed version is newer than the latest published release. A downgrade will not be offered.",
        changesTitle: "What changed in {{version}}",
        releaseNotesMissing:
          "This release has no short notes. Open the full changelog instead.",
        releasePage: "Release page",
        fullChangelog: "Full changelog",
        confirm:
          "Install keen-pbr-sb {{version}}? Routing services and the web UI will restart briefly. Review the changes on this page before continuing.",
        result: "Update log",
        waitingForLog: "Update started; waiting for the first log lines…",
        checkFailed: "Could not check for updates.",
        startFailed: "Could not start the update.",
      },
      advanced: {
        title: "Advanced routing settings",
        description:
          "Advanced settings - only change these if you know what you're doing.",
        fwmarkStartLabel: "Firewall mark starting value",
        fwmarkStartHint:
          "The starting fwmark assigned to your first outbound. Each additional outbound gets the next value in the range.",
        fwmarkMaskLabel: "Firewall mark mask",
        fwmarkMaskHintPrefix:
          "Bitmask defining which bits are used for fwmarks. Must be a continuous block of hex",
        fwmarkMaskHintSuffix: "digits, e.g.",
        tableStartLabel: "IP routing table starting value",
        tableStartHint:
          "The routing table ID assigned to your first outbound. Each additional outbound gets the next ID.",
      },
      actions: {
        saving: "Saving...",
        save: "Save",
      },
    },
    dnsServers: {
      title: "DNS Servers",
      description: "Upstream DNS servers used for domain name resolution.",
      keeneticAddress: "Keenetic built-in DNS",
      actions: {
        add: "Add DNS server",
      },
      empty: {
        title: "No DNS servers yet",
        description: "Add a DNS server to configure upstream resolution.",
      },
      loadErrorDescription:
        "We can't load DNS servers right now. Try refreshing the page.",
      headers: {
        name: "Name",
        address: "Address",
        outbound: "Outbound",
        actions: "Actions",
      },
      delete: {
        confirmWithReferences:
          'DNS server "{{serverTag}}" is currently used by {{count}} rule(s){{fallbackSuffix}}.\nDelete and automatically remove those references?',
        fallbackSuffix: " and as fallback",
      },
      deleteDialog: {
        title: "Delete DNS servers?",
        description:
          "Confirming this operation will make the following changes:",
        confirm: "Delete",
        items: {
          serverPrefix: "DNS server",
          serverSuffix: "will be deleted.",
          dnsRule: "DNS rule #{{number}} will be deleted.",
          fallback: "Fallback DNS will be changed.",
        },
      },
      bulk: {
        selected: "{{count}} selected",
        delete: "Delete selected",
        confirmDelete:
          "Delete DNS servers {{tags}}?\nAutomatically remove stale references?",
      },
      none: "none",
    },
    dnsServerUpsert: {
      createTitle: "Create DNS server",
      editTitle: "Edit DNS server",
      missingCardDescription: "The requested DNS server could not be found.",
      missingCardTitle: "Missing DNS server",
      missingDescription:
        "Return to the DNS servers table and choose a valid entry.",
      back: "Back to DNS servers",
      description:
        "This server will be available in your DNS rules and as a fallback.",
      cardDescription:
        "Choose the DNS server type and optional detour outbound.",
      editCardTitle: "Edit {{tag}}",
      fields: {
        tag: "Name",
        tagHint: "A short name for this server, used in DNS rules.",
        type: "DNS type",
        typeHint:
          "Keenetic reuses the router's current built-in DNS. Plaintext DNS uses a manually entered IP address.",
        typeOptions: {
          keenetic: "Keenetic DNS",
          static: "Plaintext DNS",
        },
        keeneticNotice: {
          description:
            "Configure DNS servers in the Keenetic web interface for this mode.",
          openLink: "Go to settings",
          navigation:
            "Go to Network Rules -> Internet safety -> DNS Configuration (Russian UI: Сетевые правила -> Интернет-фильтры -> Настройка DNS).",
          dotDohOnly:
            "If any DoT or DoH servers are configured there, only those servers will be used.",
        },
        address: "Address",
        addressPlaceholder: "1.1.1.1 or [2606:4700::1111]:53",
        addressHint:
          "The server's IP address, e.g. `1.1.1.1` or `[2606:4700::1111]:53`.",
        detour: "Make requests via Outbound",
        detourEmpty: "Not selected",
        detourPlaceholder: "Optional outbound tag",
        detourHint:
          "Optional: send DNS queries for this server through a specific outbound (e.g. a VPN).",
      },
      validation: {
        tagRequired: "Name is required.",
        tagUnique: "Name must be unique.",
        typeRequired: "DNS type is required.",
        addressRequired: "Address is required.",
        addressInvalid:
          "Address must be a valid IPv4/IPv6 value with an optional port.",
      },
      actions: {
        create: "Create DNS server",
        save: "Save DNS server",
      },
    },
    routingRules: {
      title: "Routing rules",
      description:
        "Rules that decide which outbound handles matching traffic. Evaluated top to bottom.",
      actions: {
        reorder: "Drag to reorder",
        addRule: "Add routing rule",
        enableRule: "Enable rule",
        disableRule: "Disable rule",
      },
      messages: {
        saved: "Routing rules staged. Apply new config to persist them.",
      },
      bulk: {
        selected: "{{count}} selected",
        enable: "Enable selected",
        disable: "Disable selected",
        delete: "Delete selected",
        confirmDelete:
          "Delete {{count}} routing rule(s)? This cannot be undone from this screen alone.",
      },
      empty: {
        title: "No routing rules yet",
        description:
          "Add a routing rule to direct matching traffic to an outbound.",
      },
      headers: {
        order: "Order",
        criteria: "Match",
        outbound: "Outbound",
        runtime: "Runtime",
        actions: "Actions",
      },
      criteriaLabels: {
        lists: "Lists",
        proto: "Proto",
        dscp: "DSCP",
        sourceIp: "Source IP",
        destinationIp: "Destination IP",
        sourcePort: "Source port",
        destinationPort: "Destination port",
      },
    },
    routingRuleUpsert: {
      createTitle: "Create routing rule",
      editTitle: "Edit routing rule",
      description:
        "This rule directs matching traffic to the specified outbound.",
      cardDescription:
        "Choose lists and outbound, then optionally narrow by protocol, ports, and addresses.",
      messages: {
        saved: "Routing rule staged. Apply new config to persist it.",
      },
      missing: {
        cardDescription: "The requested routing rule could not be found.",
        cardTitle: "Missing routing rule",
        description:
          "Return to the routing rules table and choose a valid entry.",
        back: "Back to routing rules",
      },
      validation: {
        atLeastOneCondition:
          "Specify at least one condition: list, DSCP, source/destination address, or source/destination port.",
        dscpRange: "DSCP must be an integer between 1 and 63.",
        outboundRequired: "Outbound tag is required.",
      },
      actions: { create: "Create rule", save: "Save rule" },
      fields: {
        lists: "Lists",
        listsPlaceholderDescription:
          "Add one or more configured list names to match for this rule.",
        noListsSelected: "No lists selected",
        listsHint: "Choose which of your lists this rule applies to.",
        proto: "Proto",
        any: "Any",
        anyLower: "any",
        protocol: "Protocol",
        protoHint: "Filter by protocol (TCP, UDP, etc.). Leave empty for any.",
        dscp: "DSCP",
        dscpHint: "Match packets with this DSCP tag. Leave empty for any.",
        sourcePort: "Source port",
        destinationPort: "Destination port",
        sourcePortHint:
          "Source port(s). Comma-separated, ranges allowed. Prefix `!` to negate.",
        destinationPortHint:
          "Destination port(s). Comma-separated, ranges allowed. Prefix `!` to negate.",
        sourceAddresses: "Source addresses",
        destinationAddresses: "Destination addresses",
        sourceAddressHint:
          "Source IP/CIDR. Comma-separated. Prefix `!` to negate.",
        destinationAddressHint:
          "Destination IP/CIDR. Comma-separated. Prefix `!` to negate.",
        outbound: "Outbound",
        selectOutbound: "Select outbound",
        configuredOutbounds: "Configured outbounds",
        outboundHint: "Which outbound should handle matching traffic.",
      },
      placeholders: {
        dscp: "46",
        sourcePort: "80,443 or 10000-20000",
        destinationPort: "443 or !53,123",
        sourceAddresses: "192.168.1.10,10.0.0.0/8",
        destinationAddresses: "2001:db8::1 or !203.0.113.0/24",
      },
    },
    outbounds: {
      groups: {
        interfaces: "Tunnels and interfaces",
        failover: "Failover groups",
        system: "System outbounds",
      },
      title: "Outbounds",
      description: "Your configured outbounds and urltest groups.",
      actions: { new: "Add outbound" },
      bulk: {
        selected: "{{count}} selected",
        delete: "Delete selected",
        confirmDelete:
          "Delete {{count}} outbound(s)? Dependencies are not validated until save.",
      },
      deleteDialog: {
        title: "Delete outbounds?",
        description:
          "Confirming this operation will make the following changes:",
        confirm: "Delete",
        items: {
          outboundPrefix: "Outbound",
          outboundSuffix: "will be deleted.",
          dependentOutboundPrefix: "Dependent urltest outbound",
          dependentOutboundSuffix: "will be deleted.",
          routingRule: "Routing rule #{{number}} will be removed.",
          ruleDetail: "{{label}}: {{value}}",
          dnsDetour: 'DNS server "{{server}}" will be changed.',
          urltestGroupChanged:
            'Group #{{group}} in urltest outbound "{{outbound}}" will be changed.',
          urltestGroupRemoved:
            'Group #{{group}} in urltest outbound "{{outbound}}" will be deleted.',
          groupOutbounds: "Outbounds",
        },
      },
      empty: {
        title: "No outbounds yet",
        description: "Add an outbound to start building routing behavior.",
      },
      headers: {
        tag: "Name",
        type: "Source",
        summary: "Details",
        runtime: "Runtime",
        actions: "Actions",
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
          'Outbound "{{outbound}}" references missing outbound tag "{{referenced}}".',
      },
    },
    outboundUpsert: {
      createTitle: "Create outbound",
      editTitle: "Edit outbound",
      editCardTitle: "Edit {{tag}}",
      description:
        "An outbound can be a single network interface, a routing table, or a urltest group that picks the fastest option.",
      cardDescription: "Configure interface or urltest outbounds.",
      missing: {
        cardDescription: "The requested outbound could not be found.",
        cardTitle: "Missing outbound",
        description: "Return to the outbounds table and choose a valid entry.",
        back: "Back to outbounds",
      },
      actions: { create: "Create outbound", save: "Save outbound" },
      common: {
        noExtraFields:
          "No additional fields are required for this type beyond the outbound tag.",
      },
      fields: {
        tag: "Name",
        tagHint:
          "A unique name for this outbound. Referenced in traffic rules and groups.",
        type: "Type",
        outboundTypes: "Outbound types",
        typeOptions: {
          interface: "Interface",
          table: "Routing table",
          urltest: "Auto-select (urltest)",
          blackhole: "Blackhole",
          ignore: "Ignore",
        },
      },
      interface: {
        title: "Interface settings",
        description:
          "Set the egress interface and optional IPv4/IPv6 gateways for this outbound.",
        interface: "Interface",
        interfacePlaceholder: "Select or type an interface",
        interfaceHint: "Egress interface name, e.g. `tun0`, `eth0`, `wg0`.",
        gateway: "Gateway (IPv4)",
        gatewayHint: "Optional IPv4 gateway for this outbound.",
        gateway6: "Gateway (IPv6)",
        gateway6Hint: "Optional IPv6 gateway for this outbound.",
      },
      table: {
        title: "Routing table settings",
        description: "Map this outbound to an existing kernel routing table.",
        field: "Table ID",
        hint: "Kernel routing table ID for this outbound.",
      },
      blackhole: {
        title: "Blackhole behavior",
        description:
          "Blackhole outbounds intentionally drop all matching traffic.",
      },
      ignore: {
        title: "Ignore behavior",
        description:
          "Ignore outbounds pass matching traffic through without policy-based routing changes.",
      },
      urltest: {
        groupsTitle: "Outbound groups (urltest)",
        groupsDescription:
          "Add outbounds to this group. The fastest responding outbound (by urltest probe) will be selected.",
        groupTitle: "Group {{index}}",
        groupDescription:
          "Priority {{index}} - higher priority groups are preferred.",
        interfaceOutbounds: "Interface outbounds",
        addOutbound: "Add outbound",
        noInterfaceOutbounds: "No interface outbounds found.",
        addInterfaceOutboundsFirst:
          "Add interface outbounds first so urltest groups have selectable targets.",
        addGroup: "Add group",
        probingTitle: "Probing and retries",
        probingDescription:
          "Configure how the urltest group probes candidates and retries failed checks.",
        probeUrl: "Probe URL",
        probeUrlHint:
          "The service fetches this URL at the configured interval to verify the interface is alive and measure latency.",
        interval: "Interval (ms)",
        intervalHint: "How often to request the Probe URL (in milliseconds).",
        tolerance: "Tolerance (ms)",
        toleranceHint:
          "Don't switch outbounds unless the latency difference exceeds this value. Prevents flapping.",
        retryAttempts: "Retry attempts",
        retryAttemptsHint:
          "Extra probe attempts before marking the outbound as failed.",
        retryInterval: "Retry interval (ms)",
        retryIntervalHint:
          "Delay between retries after a failed probe (in milliseconds).",
      },
      circuitBreaker: {
        title: "Circuit breaker - limit probing on persistent failure",
        description:
          "Prevents excessive probing when an interface or probe URL is persistently unavailable.",
        failures: "Failures before open",
        failuresHint: "Open the circuit after this many consecutive failures.",
        successes: "Successes to close",
        successesHint: "Successful probes required to close the circuit again.",
        timeout: "Open timeout (ms)",
        timeoutHint:
          "How long the circuit stays open before half-open probing begins (in ms).",
        halfOpen: "Half-open probes",
        halfOpenHint:
          "Number of probe attempts allowed during the half-open phase before the circuit fully closes or reopens.",
      },
      strictEnforcement: {
        label: "Kill-switch override",
        hint: "Override the global kill-switch setting for this outbound.",
        default: "Default (as in global config)",
      },
      validation: {
        tagRequired: "Tag is required.",
        duplicateTag: 'Outbound tag "{{tag}}" already exists.',
        missingReference:
          'Outbound "{{outbound}}" references missing outbound tag "{{referenced}}".',
      },
    },
    dnsRules: {
      title: "DNS Rules",
      description:
        "Control which DNS server is used for domains in your lists.",
      actions: {
        add: "Add DNS rule",
        enableRule: "Enable rule",
        disableRule: "Disable rule",
      },
      bulk: {
        selected: "{{count}} selected",
        enable: "Enable selected",
        disable: "Disable selected",
        delete: "Delete selected",
        confirmDelete: "Delete {{count}} DNS rule(s)?",
      },
      messages: {
        saved: "DNS configuration staged. Apply new config to persist it.",
      },
      validation: {
        invalidFallback:
          "Primary DNS servers must reference existing server tags.",
        invalidFallbackChange:
          "Cannot change fallback while DNS rules are invalid.",
        invalidResult: "Cannot save because resulting DNS rules are invalid.",
      },
      fallback: {
        title: "Primary DNS servers",
        description:
          "The ordered DNS servers dnsmasq should use when no DNS rule matches.",
        add: "Add primary DNS server",
        placeholderTitle: "No primary DNS servers selected",
        placeholderDescription:
          "Add one or more DNS servers. The order is preserved and used in generated dnsmasq config.",
        noneDefined: "No DNS servers defined on the DNS Servers page.",
        noneAvailable: "All DNS servers are already selected.",
      },
      empty: {
        title: "No DNS rules yet",
        description:
          "No rules yet - add a rule to route DNS lookups for specific lists through a chosen server.",
      },
      headers: {
        criteria: "Match",
        serverTag: "DNS server",
        allowDomainRebinding: "Domain rebinding",
        actions: "Actions",
      },
      criteriaLabels: {
        lists: "Lists",
      },
      rebinding: {
        enabled: "Allowed",
        disabled: "Blocked",
      },
    },
    dnsRuleUpsert: {
      createTitle: "Create DNS rule",
      editTitle: "Edit DNS rule",
      description:
        "This rule defines which DNS server to use for domains in a specific list.",
      cardDescription: "Set the list names and DNS server for this rule.",
      messages: { saved: "DNS rule staged. Apply new config to persist it." },
      validation: {
        notFound: "The requested DNS rule was not found.",
        fixErrors: "Fix validation errors before saving.",
        serverRequired: "Rule must reference an existing DNS server.",
        listsRequired: "Rule must include at least one list.",
        unknownLists: "Unknown lists: {{lists}}",
        duplicate: "Duplicate rule entry.",
      },
      missing: {
        cardDescription: "The requested DNS rule could not be found.",
        cardTitle: "Missing DNS rule",
        description: "Return to DNS Rules and choose a valid entry.",
        back: "Back to DNS rules",
      },
      actions: { create: "Create rule", save: "Save rule" },
      fields: {
        serverTag: "DNS server",
        selectServer: "Select DNS server",
        dnsServers: "DNS servers",
        noServers: "No DNS servers defined on the DNS Servers page.",
        listNames: "Domain lists",
        allowDomainRebinding: "Allow domain rebinding for these domains",
        allowDomainRebindingHint:
          "Enable this only when you know this domain list points to internal services. Responses for matched domains will be allowed to contain internal/private IPs (for example 192.168.0.0/16, 10.0.0.0/8, and other local network ranges).",
        listPlaceholderDescription:
          "Choose which lists this rule applies to. Matching domains will use this DNS server.",
        noListsSelected: "No lists selected",
        noLists:
          "No lists found. Please, create first filter on the Lists page.",
      },
    },
    lists: {
      title: "Lists",
      description:
        "Groups of domains and IP addresses you can use in your traffic and DNS rules.",
      actions: {
        new: "Add list",
        update: "Update",
        updateAll: "Update all",
      },
      empty: {
        title: "No lists yet",
        description:
          "Create your first list to use it in routing and DNS rules.",
      },
      headers: {
        name: "Name",
        type: "Source",
        stats: "Entries",
        rules: "Used in",
        actions: "Actions",
      },
      delete: {
        confirm: 'Delete list "{{name}}"?',
        confirmWithReferences:
          'Delete list "{{name}}" and remove its references from routing and DNS rules?',
      },
      deleteDialog: {
        title: "Delete lists?",
        description:
          "Confirming this operation will make the following changes:",
        confirm: "Delete",
        items: {
          listPrefix: "List",
          listSuffix: "will be deleted.",
          routeRuleRemoved: "Routing rule #{{number}} will be deleted.",
          routeRuleUpdated: "Routing rule #{{number}} will be changed.",
          dnsRuleRemoved: "DNS rule #{{number}} will be deleted.",
          dnsRuleUpdated: "DNS rule #{{number}} will be changed.",
        },
      },
      bulk: {
        selected: "{{count}} selected",
        refreshSelected: "Update selected (URL)",
        deleteSelected: "Delete selected lists",
        confirmDeleteSimple: "Delete lists: {{names}}?",
        confirmDeleteWithRefs:
          "Delete lists: {{names}} and remove references from routing/DNS rules where needed?",
        noUrlBacked: "None of the selected lists are URL-backed.",
      },
      location: {
        inline: "Inline",
      },
      refresh: {
        draftBlocked: "Apply draft config before updating lists.",
        updateDisabled: "Apply the staged draft before refreshing",
      },
      rule: {
        configured: "Configured",
      },
      messages: {
        refreshedOne: "List refresh finished.",
        refreshedAll: "Lists refresh finished.",
        refreshFailedOne:
          'List "{{names}}" was not updated. See logs for details.',
        refreshFailedMany:
          "{{count}} lists were not updated: {{names}}. See logs for details.",
        refreshFailedMore: "+{{count}} more",
      },
      lastUpdated: "Last updated: {{value}}",
      neverUpdated: "Never updated",
      noStats: "-",
      source: {
        url: "From a link",
        file: "From a file",
        domains: "Domain list",
        ip_cidrs: "Address list",
        empty: "Empty",
      },
    },
    listUpsert: {
      templates: {
        button: "Pick a ready-made list",
        title: "Ready-made lists",
        description: "Curated sing-box rule sets: choose a service and its URL fills the field.",
        search: "Search by name or address",
        add: "Select",
        empty: "Nothing found",
        categories: {
          ai: "AI services",
          social: "Social and messengers",
          media: "Media and streaming",
          gaming: "Games",
          developer: "Work and development",
          cloud: "Clouds and platforms",
          block: "Blocking",
          other: "Other",
        },
      },
      createTitle: "Create list",
      editTitle: "Edit list",
      editCardTitle: "Edit {{name}}",
      fallbackName: "list",
      description:
        "A list can contain domains and IPs you enter directly, load from a URL, or import from a file.",
      cardDescription:
        "Review the list source, TTL, and matching entries before saving.",
      messages: {
        created: "List staged. Apply new config to persist it.",
        updated: "List changes staged. Apply new config to persist them.",
      },
      missing: {
        cardDescription: "The requested list could not be found.",
        cardTitle: "Missing list",
        description: "Return to the lists table and choose a valid entry.",
        back: "Back to lists",
      },
      actions: {
        saving: "Saving...",
        create: "Create list",
        save: "Save list",
      },
      common: {
        title: "List settings",
        description: "Set the list identity before choosing the source.",
      },
      sourceSwitcher: {
        title: "Source type",
        description:
          "Choose which source to edit. Legacy lists with multiple saved sources stay visible until you switch.",
        confirmChange:
          "Switch source type and clear the currently filled fields?",
      },
      sourceGroups: {
        url: {
          button: "URL",
          title: "Remote URL",
          description:
            "Load list entries from a remote HTTP or HTTPS endpoint and control the cache lifetime for resolved IPs.",
        },
        file: {
          button: "File on device",
          title: "Local file",
          description: "Read list entries from a file available on the router.",
        },
        inline: {
          button: "Domains / IPs",
          title: "Domains / IPs",
          description: "Enter domains and IPs directly in the config.",
        },
      },
      dnsRule: {
        title: "DNS server for this list",
        description: "Domains from this list resolve through the selected server. Without one the list uses the primary servers.",
        none: "Not set",
      },
      quickSetup: {
        title: "Quick rule setup",
        description:
          "Optionally create linked rules together with the list. All changes are saved in one operation.",
        createRouteRule: "Create a routing rule for this list",
        selectOutbound: "Select a tunnel or another outbound",
        createDnsRule: "Create a DNS rule for this list",
        selectDnsServer: "Select a DNS server",
        noDnsServers:
          "Create a DNS server first, then it will become available here.",
        manualHint:
          "Leave the checkboxes off to configure rules manually after creating the list.",
        routeRequired: "Select an outbound for the routing rule.",
        dnsRequired: "Select a DNS server for the DNS rule.",
      },
      fields: {
        name: "Name",
        nameHint: "Stable identifier used in rules and references.",
        ttlMs: "IP cache duration (ms)",
        ttlMsHint:
          "How long to keep resolved IPs in the ipset. `0` = no timeout.",
        detour: "Make requests via Outbound",
        detourEmpty: "Not selected",
        detourPlaceholder: "Optional outbound tag",
        detourHint:
          "Optional outbound to use when downloading this list from a remote URL.",
        url: "Remote URL",
        urlHint:
          "Optional: a URL to download entries from. Combined with anything you add below.",
        file: "Absolute file path",
        fileHint:
          "Optional: a file path on the device to load entries from. Combined with other sources.",
        domains: "Domains",
        domainsHint:
          "Domains to include, one per line. `example.com` will also match all subdomains.",
        ipCidrs: "IP CIDRs",
        ipCidrsHint:
          "IP addresses or CIDR ranges, one per line. E.g. `93.184.216.34`, `10.0.0.0/8`.",
      },
      validation: {
        nameRequired: "Name is required.",
        duplicateName: "A list with this name already exists.",
        invalidTtl: "TTL must be a non-negative integer.",
      },
    },
  },
} as const

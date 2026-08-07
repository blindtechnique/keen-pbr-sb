export const enTranslation = {
  nfqws: {
    showArgs: "Show the launch line",
    hideArgs: "Hide",
    argsSummary: "{{count}} arguments, {{chars}} characters",
    repository: "Open the official nfqws2 repository",
    description:
      "Manage nfqws2, strategies, configuration, lists, Lua scripts and logs.",
    refresh: "Refresh",
    service: "nfqws2 service",
    version: "Installed version: {{version}}",
    running: "Running",
    stopped: "Not running",
    start: "Start",
    stop: "Stop",
    restart: "Restart",
    reload: "Reload configuration",
    upgrade: "Upgrade package",
    updateAvailable: "Update {{version}} is available",
    upToDate: "The latest available nfqws2 version is installed.",
    upgradeConfirmTitle: "Update nfqws2",
    upgradeConfirmDescription:
      "Version {{version}} will be installed from the official nfqws2-keenetic repository.",
    automaticBackupTitle: "Automatic backup",
    automaticBackupDescription:
      "Before updating, the panel always stores a local copy of the configuration, lists, Lua scripts and strategies. It can be restored from the operation log.",
    downloadBackupBeforeUpgrade:
      "Also download a copy of the original nfqws2 files to this computer",
    operationResult: "nfqws2 operation result",
    operationRunning: "The operation is running. Do not close this page.",
    operationSucceeded: "The operation completed successfully",
    operationFailed: "The operation failed",
    operationCompleted: "The operation completed successfully.",
    defaultStrategyCreated:
      "The package's new configuration was saved as strategy “{{name}}”.",
    closeResult: "Close message",
    rollback: "Roll back configuration",
    rollbackCompleted: "The configuration was restored from backup.",
    customConfigTitle: "A custom configuration is running",
    customConfigDescription:
      "The active nfqws2.conf matches none of the strategies in the list - that happens after editing it on the Settings tab or over ssh. Save it as a strategy, or the first Apply will overwrite it for good.",
    snapshotActive: "Save the current one as a strategy",
    snapshotActiveDescription:
      "The whole active nfqws2.conf becomes a new strategy - with every setting, port and argument it currently holds.",
    applyConfirmTitle: "Apply the strategy?",
    applyDescription:
      "The strategy \u201c{{name}}\u201d replaces nfqws2.conf entirely and the service restarts. Along with the bypass arguments this also changes what the Settings tab shows: interface, ports, policy.",
    applyOverCustomDescription:
      "The strategy \u201c{{name}}\u201d replaces nfqws2.conf entirely. What is there now is a custom configuration saved in no strategy - once applied, it cannot be brought back. Save it first with \u201cSave the current one as a strategy\u201d.",
    strategyHeaders: {
      name: "Strategy",
      origin: "Origin",
      state: "State",
      actions: "Actions",
    },
    strategyOrigin: {
      builtin: "Bundled",
      custom: "Yours",
      overridden: "Bundled, edited",
      draft: "Draft, not saved",
    },
    strategyState: {
      active: "Applied",
      inactive: "Not applied",
    },
    strategiesEmptyTitle: "No strategies yet",
    strategiesEmpty:
      "A strategy is a set of bypass parameters. Add your own, or update nfqws2 to get the bundled ones.",
    strategyEditorTitle: "Editing: {{name}}",
    strategyEditorDescription:
      "Each line is a set of nfqws arguments for one kind of traffic. Save writes the strategy to disk; Apply also restarts the service with it.",
    strategyNameDescription:
      "The name is only for you - it changes nothing except how the strategy is listed.",
    strategySaveBeforeApply: "Save the strategy first",
    editStrategy: "Open for editing",
    restoreBuiltin: "Restore the bundled one",
    restoreBuiltinDescription:
      "Your edits to \u201c{{name}}\u201d will be dropped and the strategy will return to the version shipped with nfqws2.",
    deleteStrategyTitle: "Delete the strategy?",
    deleteStrategyDescription:
      "The strategy \u201c{{name}}\u201d will be deleted. If it is currently applied, the service keeps running with the old parameters until it restarts.",
    fileHeaders: {
      name: "File",
      size: "Size",
      actions: "Actions",
    },
    fileSections: {
      lists:
        "Domains and addresses nfqws2 applies the bypass to. One file is one list; strategies reference it by name.",
      lua: "Lua scripts that extend how nfqws2 parses traffic. Rarely needed, and only if you know what you are doing.",
      logs: "What the service recorded about its work. Readable, not editable.",
    },
    fileEmpty: {
      lists:
        "Lists decide which traffic the bypass applies to. Create the first one - a list of domains, for example.",
      lua: "Scripts are not needed for normal operation. Create one only if a strategy references such a file.",
      logs: "The service has not written anything yet.",
    },
    fileEmptyTitle: "No files yet",
    fileEditorTitle: "Editing: {{name}}",
    fileDraftBadge: "unsaved",
    fileNotRemovable: "nfqws2 needs this file; it cannot be deleted",
    openFile: "Open",
    fileNameDescription: {
      lists: "The .list extension is added for you if you leave it out.",
      lua: "The .lua extension is added for you if you leave it out.",
      logs: "",
    },
    deleteFileTitle: "Delete the file?",
    deleteFileDescription:
      "The file \u201c{{name}}\u201d will be removed from the router. Strategies that reference it will stop finding their list.",
    clearLogDescription:
      "The contents of \u201c{{name}}\u201d will be erased. The service keeps writing to the same file.",
    groups: {
      scope: "Which traffic to apply to",
      scopeDescription:
        "Which interface the traffic goes through, which ports to inspect, and which devices this works for.",
      bypass: "How to bypass the block",
      bypassDescription:
        "nfqws arguments for each kind of traffic. These normally come from a ready-made strategy rather than being typed by hand.",
      other: "Other",
      otherDescription: "Settings you need while troubleshooting.",
    },
    modes: {
      MODE_AUTO: "Automatic - by lists, or to all traffic when there are none",
      MODE_LIST: "By lists only",
      MODE_ALL: "To all traffic",
    },
    fields: {
      ISP_INTERFACE: {
        label: "ISP interface",
        hint: "The interface the router uses to reach the internet. Leave empty and nfqws2 figures it out.",
      },
      TCP_PORTS: {
        label: "TCP ports",
        hint: "Ports whose traffic to inspect. 80 and 443 are ordinary web; add others only if you know why.",
      },
      UDP_PORTS: {
        label: "UDP ports",
        hint: "The same for UDP. 443 is QUIC - YouTube and other Google services.",
      },
      POLICY_NAME: {
        label: "KeeneticOS policy",
        hint: "Name of the Keenetic access policy whose devices the bypass applies to. Empty means everyone.",
      },
      POLICY_EXCLUDE: {
        label: "Invert: exclude this policy",
        hint: "The bypass works for everyone except the devices of that policy.",
      },
      IPV6_ENABLED: {
        label: "Handle IPv6",
        hint: "Turn on if your ISP hands out IPv6 and part of the traffic goes over it.",
      },
      LOG_LEVEL: {
        label: "Verbose log",
        hint: "The service records more detail. Useful while troubleshooting, otherwise it just takes space.",
      },
      NFQWS_EXTRA_ARGS: {
        label: "When to apply the bypass",
        hint: "By lists means only what the list files name. To all traffic loads the router harder.",
      },
      NFQWS_BASE_ARGS: {
        label: "Base arguments",
        hint: "Shared by every kind of traffic. Usually set by the strategy and left alone.",
        help: "nfqws2 applies these arguments to all traffic, whatever bypass method is chosen further down. The selected strategy fills them in. A wrong option here breaks the bypass entirely rather than one kind of traffic: both sites and video stop loading. Edit them only if you know what each option does — and remember what was there before.",
      },
      NFQWS_ARGS: {
        label: "Arguments for TCP",
        hint: "How to bypass blocking of ordinary web traffic - HTTP and HTTPS.",
      },
      NFQWS_ARGS_QUIC: {
        label: "Arguments for QUIC",
        hint: "QUIC is UDP on port 443: YouTube and other Google services.",
      },
      NFQWS_ARGS_UDP: {
        label: "Arguments for the rest of UDP",
        hint: "Everything on UDP other than QUIC: games, voice, some VPNs.",
      },
      NFQWS_ARGS_CUSTOM: {
        label: "Your own arguments",
        hint: "Appended to the rest. The place for what you worked out yourself.",
      },
      NFQWS_ARGS_IPSET: {
        label: "Arguments for ipset addresses",
        hint: "Applied to traffic going to IP addresses from an ipset, rather than by domain.",
      },
    },
    tabs: {
      ariaLabel: "nfqws2 sections",
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
    saveDrafts: "Save drafts",
    saveAndRestart: "Save and apply",
    draftCount: "Modified files: {{count}}",
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
    backup: {
      button: "Backups",
      title: "nfqws2 backups",
      description:
        "Back up or restore the configuration and lists independently.",
      configTitle: "nfqws2 configuration",
      configDescription:
        "Configuration files, Lua scripts, and user strategies.",
      listsTitle: "nfqws2 lists",
      listsDescription: "All user and service .list files.",
      allTitle: "Everything together",
      allDescription: "Configuration and lists in a single backup.",
      download: "Download",
      restore: "Restore",
      downloaded: "The backup was created and downloaded.",
      restoreTitle: "Restore nfqws2",
      restored: "The nfqws2 files were restored and the service restarted.",
      scopeMissing: "The file does not contain the selected nfqws2 section.",
      unsavedBlocked:
        "Restore is unavailable: save or discard the unsaved changes in this section first.",
    },
  },
  configTransfer: {
    export: "Export",
    import: "Import",
    exportAll: "Export configuration and lists",
    importAll: "Import configuration and lists",
    imported: "Import completed",
    exported: "The export was prepared and downloaded.",
    exportFailed: "Failed to create the export file.",
    replaceOutboundConflicts:
      "Replace existing routes and groups tagged {{tags}}? If cancelled, conflicting entries will be skipped.",
    replaceTransportConflicts:
      "Replace existing VPN and proxies tagged {{tags}}? If cancelled, conflicting entries will be skipped.",
    transportSecretsWarning:
      "The export contains connection links, passwords, and other VPN or proxy secrets. Save it to this computer?",
    invalidFormat: "The file is not a compatible keen-pbr-sb export.",
    replaceLists:
      "Replace all existing lists? Choose Cancel to merge them instead.",
    replaceRules:
      "Replace all routing rules? Choose Cancel to append imported rules instead.",
    mapOutbound:
      "Route “{{missing}}” does not exist. Select one of: {{available}}",
    outboundRequired:
      "Every imported rule must be mapped to an existing route or group.",
  },
  auth: {
    title: "Sign in to keen-pbr-sb",
    description: "Authenticate to open routing management.",
    otherManagement: "Open internet access",
    username: "Username",
    password: "Password",
    showPassword: "Show password",
    hidePassword: "Hide password",
    cannotSignIn: "Cannot sign in",
    supportCenter: "Support center",
    signIn: "Sign in",
    signingIn: "Signing in…",
    signOut: "Sign out",
    invalidCredentials: "Invalid username or password.",
    unavailable: "The authentication service is unavailable.",
    unavailableTitle: "Unable to verify access",
    retry: "Try again",
    credentialsHint:
      "Use the sign-in method selected in keen-pbr-sb settings. When Keenetic verification is enabled, enter the router web interface credentials.",
  },
  common: {
    // Labels of shared interface primitives. They used to be hardcoded in
    // English inside components/ui/*, so a Russian user saw "Close" on the
    // dialog close button.
    chrome: {
      sidebar: "Sidebar",
      toggleSidebar: "Collapse or expand the menu",
      closeDialog: "Close dialog",
      closePanel: "Close panel",
      close: "Close",
      skipToContent: "Skip to content",
    },
    help: {
      about: "About this section",
    },
    moreControls: "More",
    expandable: {
      more: "Read more",
      less: "Show less",
    },
    loading: "Loading the page",
    tableSearch: {
      clear: "Clear search",
      results: "Found {{count}} of {{total}}",
      empty: "Nothing matches. Change the query or clear the search.",
    },
    setupFromCatalog: "Set up from the catalogue",
    retry: "Try again",
    updateStatus: {
      available: "Update available",
      current: "No updates",
      checking: "Checking for updates",
      unavailable: "Update check unavailable",
    },
    dependencies: {
      title: "Depends on this: {{count}}",
      more: "{{count}} more",
      collapse: "Collapse",
      none: "Nothing depends on this - deleting it breaks nothing",
      kind: {
        routingRule: "Routing rules:",
        dnsRule: "DNS rules:",
        dnsServer: "DNS servers:",
        failoverGroup: "Groups:",
        list: "Lists:",
        listRefresh: "URL list refresh:",
      },
      brokenReference: {
        missingList: "{{owner}} → list {{target}}",
        listDetour: "List {{list}} → {{target}}",
        listRefresh: "URL list updates → {{target}}",
      },
    },
    listRefreshRoute: {
      primary: "Primary download route",
      primaryEmpty: "System route",
      primaryPlaceholder: "Select a primary route",
      primaryHint:
        "If the primary route is unavailable, fallback routes are tried strictly in order.",
      fallbacks: "Fallback download routes",
      addFallback: "Add a fallback route",
      noFallbacks: "No fallback routes are available",
      fallbackLimit: "Up to three fallback routes can be selected",
      fallbackPlaceholder: "No fallback routes selected",
      fallbackPlaceholderDescription:
        "They are tried in order if the download fails.",
      fallbackHint:
        "Used only after a network or HTTP failure on the primary route. A direct connection is not added after the configured chain.",
      systemDirect: "system route",
    },
    language: "Language",
    theme: "Theme",
    reportIssue: "Report an issue",
    enabled: "Enabled",
    disabled: "Disabled",
    close: "Close",
    cancel: "Cancel",
    save: "Save",
    saving: "Saving…",
    openAdvancedEditor: "Advanced editor",
    unsavedChanges: {
      title: "Discard changes?",
      description:
        "This form has unsaved changes. Closing it now will discard them.",
      continueEditing: "Continue editing",
      discard: "Discard",
      advancedEditorDisabled:
        "Save or discard the changes in this form before switching views.",
    },
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
      reorderItem: "Move {{item}}",
      reorderItems: "Change order",
    },
    listUsage: {
      usedElsewhere: "Also in: {{summary}}",
    },
    interfacePicker: {
      open: "Open interface picker",
      kinds: {
        bridge: "network segment (bridge)",
        ethernet: "Ethernet port",
        firmwareWg: "firmware WireGuard/AWG",
        keenPbr: "keen-pbr tunnel",
        ppp: "PPP connection",
        service: "service interface",
        tun: "TUN tunnel",
        wifiAp: "Wi-Fi access point",
        wireguard: "WireGuard",
        wisp: "Wi-Fi uplink (WISP)",
      },
      empty: "No interfaces found.",
      notExists: "(not exists)",
      notFound: "Interface does not exist.",
    },
    validation: {
      tagNamePattern:
        "Can only contain a-z, 0-9 and underscores. Max 24 characters, must start with a letter.",
    },
    selection: {
      select: "Select",
      done: "Done",
      selectAll: "Select all visible rows",
      selectAllShort: "Select all",
      selectRow: "Select {{rowLabel}}",
    },
  },
  runtime: {
    healthy: "Healthy",
    notHealthy: "Not healthy",
    activeOutbound: "Active route: {{value}}",
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
      outbounds: "Routes and groups",
      transports: "VPN and proxies",
      routesAndTunnels: "VPN, proxies, groups",
      rules: "Rules",
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
    nfqwsUpdateAvailable: "nfqws2 update {{version}} is available",
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
    emptyTitle: "No active connections",
    title: "Connections",
    description:
      "Active connections and up to 1,500 recent records. DNS traffic observed by keen-pbr adds the last known domain next to the exact IP. Data refreshes every 3 seconds.",
    filter: "Filter by device, domain, address, or state",
    activeOnly: "Active only",
    loadMore: "Load more ({{loaded}} of {{total}})",
    loadingMore: "Loading...",
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
    naiveComponent: {
      title: "Naive needs a separate component",
      description:
        "NaiveProxy runs on Chromium's network stack, which sing-box keeps in a separate library of several dozen megabytes. It is not installed with the package so it does not take up room on routers that never use naive. It can be fetched now, from the same sing-box release that is installed.",
      install: "Fetch the component",
      installing: "Fetching…",
      installed: "Component installed, the VPN or proxy can start",
      failed: "Could not fetch the component",
    },
    latencyValue: "{{value}} ms",
    latencyAge: "{{seconds}}s ago",
    latencyRefresh: "Measure now",
    latencyRefreshFailed: "Could not start the check",
    traffic: {
      receive: "Receive",
      transmit: "Transmit",
      received: "Received",
      transmitted: "Sent",
      chart: "Receive and transmit chart",
      showChart: "Show chart",
      hideChart: "Hide chart",
    },
    dnsDetour: "DNS through this tunnel",
    singBoxMissing: {
      title: "sing-box is not installed",
      description:
        "VLESS, VMess, Trojan, Shadowsocks and other managed proxy connections require sing-box. Run the keen-pbr-sb installer over SSH and select the tested version.",
    },
    title: "VPN and proxies",
    description:
      "Managed VPN and proxies that provide interfaces for keen-pbr routing.",
    tabs: {
      all: "All",
      other: "Other",
      ariaLabel: "VPN and proxy types",
    },
    headers: {
      name: "Name",
      state: "State",
      latency: "Latency",
      usedBy: "Used by",
      actions: "Actions",
    },
    groups: {
      managed: "keen-pbr-sb tunnels and proxies",
      native: "KeeneticOS interfaces",
      nativeDescription:
        "Created by the router firmware. keen-pbr-sb only shows them: starting, restarting or deleting such an interface happens in the Keenetic web configurator. Here you can point a route at it.",
      orphan: "Routes without a tunnel",
      orphanDescription:
        "Normally there are none: a route is created together with its tunnel. These point at interfaces keen-pbr does not manage - for example, another Entware package's tunnel.",
    },
    refresh: "Refresh",
    add: "Add VPN or proxy",
    unavailable: "VPN and proxy manager unavailable",
    empty: "No VPN or proxies configured.",
    emptyTitle: "No VPN or proxies yet",
    processMode: {
      action: "sing-box mode",
      unavailable:
        "Process mode settings are unavailable. Update keen-pbr-sb and transport-manager.",
      title: "sing-box process mode",
      description:
        "Choose how managed sing-box proxies run. This setting does not affect native KeeneticOS tunnels.",
      modes: {
        isolated: {
          label: "Isolated",
          description:
            "Each proxy runs in its own process. This uses more memory, but one proxy failure does not stop the others.",
        },
        shared: {
          label: "Shared",
          description:
            "All managed proxies run in one process. This uses less memory, but the process becomes a shared failure boundary.",
        },
      },
      restartWarning:
        "Applying this setting restarts every managed sing-box proxy and interrupts its current sessions.",
      apply: "Apply",
      applying: "Applying…",
      applied: "sing-box process mode changed",
    },
    interface: "Interface",
    server: "Server",
    connection: "Connection",
    technicalTag: "Technical tag",
    interfaceName: "Interface name",
    pathConfidence: "Detection source",
    details: {
      show: "Show details",
      hide: "Hide details",
    },
    loopProtection: {
      action: "Exclude server from tunnel",
      confirm:
        "Add {{server}} to the first pass-through rule? This creates the transport_servers list, an ignore route named transport_bypass, and a highest-priority routing rule.",
      saved: "Routing-loop protection was added",
      tagConflict:
        "Tag {{tag}} is already used by another route type. Rename it and try again.",
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
    started: "VPN or proxy start requested",
    stopped: "VPN or proxy stop requested",
    restarted: "VPN or proxy restart requested",
    nativeManagedExternally:
      "This native interface is managed by KeeneticOS or another service.",
    nativeInterface: {
      keeneticOwner: "KeeneticOS",
      managedByFirmware: "This interface is managed by KeeneticOS",
      logicalName: "Keenetic interface",
      kernelName: "System interface",
      protocol: "Protocol",
      role: "Role",
      roleClient: "Client",
      roleServer: "Server",
      roleUnknown: "Unknown",
      liveState: "Live state",
      liveUp: "Present and enabled",
      liveDown: "Present but disabled",
      liveUnavailable: "Not found in the kernel inventory",
      liveUnavailableShort: "No data",
      connectedState: "Connection",
      connected: "Connected",
      disconnected: "Disconnected",
      linkState: "Link",
      linkUp: "Link up",
      linkDown: "Link down",
      latency: "Latency",
      boundRoute: "Route",
      routeNotConfigured: "Not configured",
      management: "Management",
      managementReadOnly: "Read only",
      managementUnsupported: "Not supported",
      managementReady: "The interface is ready for safe management.",
      managementReadinessUnavailable:
        "The installed backend does not report management readiness yet.",
      managementBlockers: {
        unsupported_kind: "Editing this interface type is not supported yet",
        unsupported_role:
          "Server interfaces will be managed in a separate section",
        role_unknown: "KeeneticOS did not report the interface role",
        kernel_identity_unresolved:
          "The KeeneticOS and Linux interface identities could not be matched safely",
        typed_rci_unavailable: "Typed KeeneticOS commands are not enabled yet",
        automatic_backup_unavailable:
          "A complete restorable interface snapshot is not available yet",
        ownership_unknown: "The interface owner has not been established",
        optimistic_revision_unavailable:
          "Concurrent-change protection is not enabled yet",
      },
      unknown: "Unknown",
      unresolved: "Not resolved",
      routeNotClient:
        "Only interfaces confirmed by KeeneticOS as client tunnels can be attached to a route.",
      routeUnresolved:
        "A route cannot be created until KeeneticOS resolves the Linux interface name.",
      routeNotLive:
        "A route can only be created while the kernel interface is present and enabled.",
      routeConfigUnavailable:
        "A route cannot be created until the current configuration is loaded.",
      hide: "Hide from the panel",
      restore: "Restore to the panel",
      showHidden: "Show hidden ({{count}})",
      hideHidden: "Stop showing hidden interfaces",
    },
    deleteTitle: "Delete VPN or proxy?",
    deleteDescription:
      "The managed process will be stopped and its definition removed.",
    deleteWithRouteDescription:
      "Deleting this tunnel also deletes its route. The list below shows what that touches; route changes go to the draft and take effect when the config is applied.",
    routeStagedForDelete:
      "The tunnel's route was removed from the draft - apply the configuration for the change to take effect.",
    deleteTunnelAfterRouteFailed:
      "The route is already removed from the draft, but the tunnel could not be deleted. Retry deleting the tunnel or discard the draft.",
    killSwitchStaged:
      "The kill-switch change was added to the draft - apply the configuration for it to take effect.",
    configMessages: {
      create: "VPN or proxy created",
      update: "VPN or proxy updated",
      delete: "VPN or proxy deleted",
    },
    form: {
      createOutbound: "Create a route now",
      createOutboundHint:
        "The route appears in the shared list with the same name and can be picked in routing rules straight away.",
      outboundExists: "A route tagged {{tag}} already exists",
      createTitle: "Add VPN or proxy",
      editTitle: "Edit VPN or proxy",
      missingTitle: "VPN or proxy not found",
      missingDescription:
        "Return to the VPN and proxies list and choose an existing entry.",
      back: "Back to VPN and proxies",
      loadErrorTitle: "Transport data could not be loaded",
      loadErrorDescription:
        "Check that the service is available and try again. Saving is disabled to avoid overwriting the current configuration.",
      description:
        "Expose a native interface or a scoped proxy TUN to keen-pbr.",
      tag: "Tag",
      tagHint:
        "1–24 characters: start with a lowercase Latin letter, then use only a–z, 0–9 and underscore. Example: my_tunnel.",
      sourceMode: "How to add",
      displayName: "Friendly name",
      displayNamePlaceholder: "For example, Netherlands - primary",
      displayNameHint:
        "Shown in the interface instead of the technical tag. The tag stays unchanged, so routes and groups keep working.",
      displayNameInvalid: "Enter a name — 1 to 80 characters.",
      useAliasSuggestion: "Use “{{name}}”",
      advancedSettings: "Advanced settings",
      simpleSettings: "Simple settings",
      technicalSettings: "Advanced technical settings",
      technicalIdentityImmutable:
        "The technical tag and interface name cannot change after creation because routes reference them.",
      backendUpdateRequired:
        "The installed backend does not support tunnel aliases. Install this version's IPK, then save again.",
      type: "Type",
      native: "Native interface",
      nativeInterface: "Keenetic interface",
      nativeInterfacePlaceholder: "Select a Keenetic interface",
      nativeInterfaceHidden: "hidden",
      nativeInterfaceUnavailable: "unavailable",
      nativeInterfaceHint:
        "Hidden interfaces remain in this list and are clearly marked. Only a client interface with a resolved system name can be routed.",
      singBox: "sing-box connection",
      singBoxLegacy: "sing-box (legacy VLESS configuration)",
      interface: "Interface name",
      autoStart: "Start automatically",
      countryDisplay: "Server country",
      geo: {
        disabled: "Do not detect or show a country",
        manual: "Set the country manually",
        auto: "Detect automatically (at your own risk)",
        autoWarning:
          "The server host/IP and resolved IP will be sent to ipwho.is over the router's current route. No request is made without this explicit choice.",
        countryPlaceholder: "Select a country",
      },
      shareLink: "Connection link",
      shareLinkHint:
        "Supports VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC, AnyTLS, SOCKS and HTTP proxy links.",
      outboundJson: "sing-box connection JSON",
      outboundJsonHint:
        "Advanced mode for any connection type supported by the installed sing-box version. The tag is assigned automatically.",
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
      title: "This VPN or proxy is not used by a route yet",
      description:
        "First create an Interface route for this interface. For automatic switching, create a group and add two or more interface routes to it.",
      createOutbound: "Create route",
      createFailover: "Create group",
      bindOutbound: "Create route",
      alreadyBound: "Already linked to “{{tag}}”",
      openOutbound: "Open the route",
      noTraffic:
        "Nothing is routed here, so no traffic will use this transport.",
    },
    usedBy: "Used by:",
    usedByNone: "Not bound to a route",
    states: {
      connected: "Running",
      down: "Down",
      starting: "Starting",
      up: "Up",
      degraded: "Degraded",
    },
  },
  brand: {
    logoAlt: "keen-pbr-sb logo",
    tagline: "Routing, VPN, and Keenetic network services in one interface.",
    openMenu: "Open menu",
    closeMenu: "Close menu",
    hideMenu: "Collapse menu",
    showMenu: "Expand menu",
  },
  headerHealth: {
    healthy: "All systems are operating normally",
    attention: "Some systems require attention",
    failed: "Some systems are not working",
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
  lifecycle: {
    running: "Applying changes",
    runningDescription: "keen-pbr is executing the operation step by step.",
    success: "Operation completed",
    successDescription: "All stages completed successfully.",
    error: "Operation failed",
    errorDescription: "Remaining stages were skipped. Check the failed stage.",
    dismiss: "Dismiss",
    stages: {
      validate_config: "Validate configuration",
      commit_and_apply: "Commit and apply",
      start_routing: "Start routing",
      stop_routing: "Stop routing",
      restart_routing: "Restart routing",
    },
  },
  overview: {
    summary: {
      healthy: {
        title: "Everything is fine",
        description: "Routing, DNS, VPN, and proxies are operating normally.",
      },
      waiting: {
        title: "Loading system state",
        description:
          "Services are being queried; current state will appear automatically.",
      },
      degraded: {
        title: "Attention required",
        description: "A routing, DNS, or service health check has failed.",
      },
      routing: "Routing",
      configuration: "Lists: {{lists}} · Rules: {{rules}}",
      draft: "Unsaved draft",
      attention: {
        ariaLabel: "Sections requiring attention",
        service: "Check services",
        dns: "Check DNS",
        routing: "Check routing",
        outbounds: "Problem routes: {{count}}",
      },
    },
    router: {
      title: "Router",
      unavailable:
        "Router details are unavailable: the firmware is not answering service requests.",
      cpu: "CPU",
      memory: "Memory",
      memoryValue: "{{used}} MB / {{total}} MB ({{percent}}%)",
      memoryValueCompact: "{{percent}}% · {{used}}/{{total}} MB",
      memoryTotalOnly: "{{total}} MB",
      disk: "Entware disk",
      diskValue: "{{used}} MB / {{total}} MB ({{percent}}%)",
      diskValueCompact: "{{percent}}% · {{used}}/{{total}}",
      capacityMb: "{{value}} MB",
      capacityGb: "{{value}} GB",
      wan: "WAN address",
      clients: "Clients",
      clientsValue: "{{active}} of {{total}}",
      firmware: "Firmware",
      uptime: "Uptime",
      uptimeValue: "{{days}}d {{hours}}h {{minutes}}m",
      uptimeHoursValue: "{{hours}}h {{minutes}}m",
      uptimeMinutesValue: "{{minutes}}m",
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
      badgeTransitioning: "In progress",
      restart: "Restart",
      restartRequested: "Restart requested",
      restartComplete: "Restart complete: routing and DNS are ready",
      restartFailed: "Restart failed",
      restartFailedDetail: "Restart failed: {{error}}",
      switchFailed: "Could not switch the service",
      title: "Services",
      singbox: "sing-box",
      nfqws: "nfqws2",
      transportsRunning: "{{running}} of {{total}} running",
      noTransports: "No VPN or proxies configured",
      notInstalled: "Not installed",
      running: "Service is running",
      stopped: "Service is stopped",
      badgeUp: "Running",
      badgeDown: "Stopped",
      badgeAbsent: "None",
    },
    pageDescription: "Overview of routing runtime, routes, VPN, and proxies",
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
    routeTraffic: {
      title: "Where the traffic goes",
      description:
        "Share of bytes received and sent per route since its interface came up. This is not a daily total: the panel keeps no persistent accounting.",
      total: "Total",
      rest: "Others",
      idle: "Route interfaces are up, but no traffic has passed through them yet.",
      unavailable:
        "Traffic counters are not available for the route interfaces.",
      loadErrorTitle: "Unable to load traffic counters",
      loadErrorDescription:
        "The dashboard could not read the current interface inventory.",
      idleCounters: "Routes with no traffic yet: {{count}}.",
      unavailableCounters: "Routes without available counters: {{count}}.",
    },
    outbounds: {
      liveTraffic: "Traffic through used VPN and proxies",
      trafficCountersHint:
        "A tunnel interface counts only traffic on that path, while WAN counts all traffic on the physical connection. The values therefore do not have to match.",
      connected: "Connected",
      connectedFor: "Connected {{duration}}",
      disconnected: "Disconnected",
      waitingForTraffic: "Waiting for traffic statistics…",
      dayShort: "d",
      summary: {
        tunnels: "Into tunnels - {{count}} lists",
        direct: "Direct - {{count}}",
        blocked: "Blocked - {{count}}",
      },
      listCount: "Lists: {{count}}",
      idleSummary: "Unused — {{count}}",
      idleNames: "{{names}} — all healthy",
      hint: {
        table: "Traffic goes straight through the provider, past the tunnels",
        tableTunnel:
          "Traffic follows a {{protocol}} VPN or proxy routing table",
        blackhole: "Connections are not let out",
        ignore: "Traffic passes without changing its route",
        groupVia: "Going through {{active}}, {{backup}} on standby",
        groupViaOnly: "Going through {{active}}",
        groupBackup: "Backup: {{backup}}",
        groupIdle: "No exit in the group is answering",
      },
      activeMember: "Active: {{name}}",
      issue: {
        interfaceUnreachable:
          "The tunnel is not up, so the system has nowhere to send traffic through it. Usually that means the transport is stopped or still starting.",
        routeMissing: "No active route is installed",
        selectionMismatch: "The selected route does not match the active route",
        probeTimeout: "The availability check timed out",
        connectionRefused: "The remote endpoint refused the connection",
        networkUnreachable: "The network or endpoint is currently unreachable",
        dnsFailed: "The remote endpoint address could not be resolved",
        permissionDenied: "The system could not perform the access check",
        cannotVerify:
          "Cannot verify this route. The check could not be tied to this transport, so a successful reply may have come over the router's own connection instead of through the tunnel.",
        degraded: "The route is responding unreliably",
        unavailable: "No route is currently available",
        member: "{{name}}: {{reason}}",
        open: "Open routes and groups",
      },
      members: "{{count}} in group",
      kind: {
        failover: "Groups",
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
      title: "Routes and groups",
      loadError: "Unable to load route and group health.",
      emptyTitle: "No routes or groups configured",
      emptyDescription: "Add a route or group to see its health.",
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
        outbound: "Route {{name}}",
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
          outbounds: "Routes and groups status",
          names: "Names of lists, routes, and interfaces",
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
          "The browser went out, but the probe saw no lookup. That also happens when everything is fine: the address was already cached, or the browser resolves through its own DNS past the router. Check from a computer to be sure.",
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
    backup: {
      title: "Backup",
      description:
        "Pick what to include and download a single keen-pbr-sb configuration file.",
      sectionTitle: "What goes in",
      sectionDescription: "Choose the sections to save.",
    },
    restore: {
      title: "Restore",
      description:
        "Restore selected groups from a file, or roll back the last change.",
      sectionTitle: "Restore source",
      sectionDescription:
        "Choose a saved copy or the last automatically saved state.",
    },
    catalog: {
      routeRuleName: "Catalog — lists: {{count}}",
      title: "List catalogue",
      description:
        "Ready-made sets of domains and rules. Pick the ones you want and say where their traffic should go.",
      categoriesAriaLabel: "Catalog categories",
      source: "Source:",
      updatedAt: "updated {{date}}",
      count: "lists: {{count}}",
      downloadVia: "Download via",
      directly: "Directly",
      checkNow: "Check now",
      refreshed: "Catalogue updated",
      refreshFailed:
        "Could not refresh; showing the previous catalogue. Try downloading through a tunnel.",
      searchPlaceholder: "Search by name",
      empty: "Nothing found",
      emptyTitle: "Nothing matched",
      ruleSet: "rule set",
      domains: "{{count}} domains",
      cidrs: "{{count}} CIDRs",
      domainsAndCidrs: "{{domains}} domains · {{cidrs}} CIDRs",
      actionTunnel: "tunnel",
      actionBlock: "block",
      alreadyAdded: "already added",
      selected: "Selected: {{count}}",
      addTunnel: "Add a tunnel",
      routeTo: "Route to",
      blockSelected: "The selected lists will be blocked",
      mixedSelection: "Routing and blocking lists must be added separately.",
      mixedSelectionShort: "Add routing lists first, then add blocking lists.",
      invalidSelection: "The selected items do not contain importable data.",
      configUnavailable:
        "Could not reload the current configuration. Nothing was changed.",
      add: "Add",
      added: "Lists added: {{count}}",
      installed: "Already added",
      partial: "Partially added",
      coveredByInstalled: "Included in “{{name}}”",
      coveredBySelection: "Selected through “{{name}}”",
      ipCompanionBadge: "+ IP",
      ipCompanionHint:
        "A separate IP set will be added together with the primary list ({{count}}).",
      ipCompanionInline: "Also included: {{name}} - {{count}} IP subnets",
      ipCompanionRemote: "Also included: {{name}} - URL-updated IP list",
      ipCompanionGeneric: "Also included: {{name}} - IP list",
      risks: {
        title: "Please note",
        broadTrafficScope:
          "This list covers a very large part of the internet. All matching traffic will use the selected route.",
        requiresAcceptance:
          "A separate confirmation will be required before applying.",
        unknown: "The catalogue reported a risk: {{code}}.",
      },
      refreshState: {
        success: "Succeeded: {{date}}",
        successVia: "Succeeded: {{date}} · via {{detour}}",
        attempt: "Last attempt: {{date}}",
        attemptVia: "Last attempt: {{date}} · via {{detour}}",
        error: "Error: {{message}}",
        neverSucceeded: "not updated yet",
        neverAttempted: "not attempted yet",
      },
      priorityGuard: {
        title: "Blocking-rule priority accounted for",
        description:
          "The new rule will be placed before these blocking rules: {{rules}}. Rules are checked from top to bottom, so a shared CDN address cannot be blocked before the selected route handles it. Existing rules keep their current order.",
      },
      naming: {
        title: "Names for the new items",
        description:
          "The catalogue suggests friendly names. Edit or clear them. Before applying, the server checks the current config, catalogue sources, and rule placement itself.",
        listName: "List name",
        routeRuleName: "Routing rule name",
        dnsRuleName: "DNS rule name",
        dnsRuleHint:
          "A DNS rule will be created for {{server}}, which uses the selected route.",
        blackholeHint:
          "No system blocking output exists yet. It will be created automatically and used only by this rule.",
        confirm: "Add",
      },
      setup: {
        preview: "Check",
        applying: "Adding…",
        previewReady: "Setup checked",
        previewSummary:
          "New lists: {{lists}}. Routing rules: {{routes}}. Route: {{route}}. DNS rules: {{dnsRules}}; server: {{dns}}.",
        batchPolicyTitle: "One shared setup without redundant rules",
        batchPolicyOutbound:
          "This session creates at most one shared routing rule for the selected lists and related IP sets. One shared DNS rule is created for all domain lists; IP sets are not added to it. Lists already covered by the selected route are not duplicated; after adding, you can split or fine-tune the rules in the editor.",
        batchPolicyBlock:
          "This session creates at most one shared rule for the selected blocking lists. Lists already covered by blocking are not duplicated, and no DNS rule is created for blocking.",
        batchPolicyDirect:
          "The selected lists will be added without a routing rule or DNS rule because the direct route is selected.",
        planTitle: "Lists in the checked plan",
        ipListCidrs: "IP list · {{count}} subnets",
        ipListRemote: "IP list · updated from URL",
        ipList: "IP list",
        mixedList: "Domains and IP addresses",
        domainList: "Domains",
        remoteList: "URL-backed list",
        localList: "Local list",
        willAdd: "will be added",
        willReuse: "already added",
        applied: "Catalog setup applied",
        alreadyInstalledTitle: "Already installed",
        alreadyInstalled:
          "{{lists}} already exists in the configuration. Duplicates will not be created; the preview below shows whether any related rules are still missing.",
        alreadyInstalledButton: "Already installed",
        noRoute: "not created",
        noDnsRule: "rule not created",
        automaticDnsHint:
          "A matching DNS server is selected automatically for the route. If none exists, the wizard creates a separate available plain DNS through that route without changing primary DNS servers.",
        warningTitle: "Review required",
        acceptWarnings:
          "I have reviewed the warnings and agree to apply this exact checked plan.",
        warnings: {
          sourceDetourNotFound:
            "The selected download route no longer exists. The list will be added without it.",
          sourceDetourNotRoutable:
            "The selected route cannot carry downloads. The list will be added without it.",
          sourceDetourNotApplicable:
            "The selected list has no remote file, so it does not need a download route.",
          dnsAutomaticUnavailable:
            "No free built-in DNS server is available for this route. Select a compatible DNS server manually in the advanced editor.",
          dnsIgnoredForBlock: "A DNS rule is not created for a blocking list.",
          dnsDetourMissing:
            "The selected DNS server is not attached to the route. Check that it can resolve domains through the intended output.",
          dnsDetourMismatch:
            "The DNS server uses a different route. Name resolution and application traffic may leave through different outputs.",
        },
      },
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
      tabs: {
        ariaLabel: "Settings sections",
        general: "General",
        incoming: "Incoming connections",
        access: "Access",
        logging: "Logging",
        advanced: "Advanced",
        maintenance: "Maintenance",
      },
      incoming: {
        title: "Incoming connections",
        description:
          "Choose inbound interfaces and configure how clients of native Keenetic VPN servers participate in keen-pbr-sb routing.",
      },
      backup: {
        title: "Backup and restore",
        description:
          "Create a selective backup or restore keen-pbr-sb settings from a previously saved file.",
        create: "Create backup",
        restore: "Restore from backup",
        groups: {
          general: "General settings",
          transports: "VPN and proxies",
          outbounds: "Routes and groups",
          dns: "DNS settings",
          routing: "Lists and routing rules",
          nfqws_config: "nfqws2 configuration",
          nfqws_lists: "nfqws2 lists",
        },
        dialog: {
          backupTitle: "Backup",
          backupDescription:
            "Pick the data and download a single keen-pbr-sb configuration file.",
          restoreTitle: "Restore",
          restoreDescription:
            "Restore the selected groups from a file, or roll back the last change.",
        },
        secretsWarning:
          "If VPN and proxies are selected, the file contains their UUIDs, passwords and keys in plain text. Keep the copy somewhere safe and do not pass it on.",
        validationNote:
          "The configuration is validated before it is written and applied only after the check passes.",
        createButton: "Create and download",
        createPending: "Creating\u2026",
        created: "Backup created",
        createFailed: "Could not create the backup",
        readFailed: "Could not read the backup",
        restored: "Configuration restored",
        rolledBack: "Rolled back",
        actionFailed: "The operation did not complete",
        confirmRestore: "Restore \u201c{{filename}}\u201d?",
        confirmRollback: "Roll the configuration back?",
        restoreHint:
          "A rollback copy is created automatically before the change.",
        rollbackHint:
          "The state from before the last update or restore will be brought back.",
        cancel: "Cancel",
        confirm: "Confirm",
        confirmPending: "Working\u2026",
        rollbackButton: "One-click rollback",
        chooseFile: "Choose a backup file",
      },
      remoteAccess: {
        title: "Access from outside",
        description:
          "Reach the web interface from the internet, not just from the home network.",
        enabled: "Allow access from the internet",
        port: "External port",
        portHint:
          "The port the panel answers on from outside. Pick something non-obvious.",
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
        viewer: {
          open: "Open log",
          title: "keen-pbr-sb log",
          description:
            "The latest service log lines. Viewing them does not change the router.",
          ariaLabel: "keen-pbr-sb log contents",
          refresh: "Refresh",
          refreshing: "Refreshing…",
          loading: "Loading log…",
          empty: "The log is empty.",
          failed: "Could not read the log",
        },
        diagnostics: {
          download: "Download diagnostics",
          downloading: "Collecting diagnostics…",
          failed: "Could not collect diagnostics",
          title: "Diagnostics file",
          description:
            "The file includes technical router and service details, route and tunnel state, and the latest log lines.",
          trustWarning:
            "Nothing is uploaded: the file is downloaded only to this computer. Share it only with someone you trust because logs may contain server addresses and device names.",
          includeLists:
            "Include list contents and subscription URLs (hidden by default)",
          confirm: "Download file",
        },
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
        providerRouterHint:
          "The Keenetic firmware checks the credentials; keen-pbr-sb never stores the password.",
        providerLocalHint:
          "Login and password are stored in auth.json on the router.",
        endpoint: "Router web interface address",
        endpointMode: "Router address discovery",
        endpointModeAuto: "Automatically via NDMS",
        endpointModeManual: "Manually",
        endpointModeAutoHint:
          "Keenetic reports its local address and port through NDMS. Currently detected: {{endpoint}}.",
        endpointModeManualHint:
          "Use only a local address assigned to the router itself.",
        endpointFallbackAdvanced: "Advanced settings",
        endpointFallback: "Fallback address",
        endpointFallbackHint:
          "Optional. Used only while the local NDMS service is temporarily unavailable.",
        endpointUnavailable: "temporarily unavailable",
        username: "Username",
        password: "Password",
        verifyHint:
          "Enter the router credentials: they are verified before saving so you cannot lock yourself out.",
        localStoreHint:
          "Set the login and password you will use for keen-pbr-sb.",
        save: "Save login method",
        saved: "Login settings saved, sign in again",
      },
      title: "Settings",
      description: "Global defaults that apply to all your routes and rules.",
      saved: "Settings staged. Apply new config to persist them.",
      general: {
        title: "General",
        description: "Default behavior for all routes.",
        strictEnforcementLabel:
          "Block traffic when a route drops (kill-switch)",
        strictEnforcementHint:
          "If a VPN or interface goes offline, traffic matching its rules is blocked instead of falling back to the main routing table. Can be overridden per route.",
        strictEnforcementHelp:
          "A kill switch protects against leaks. Normally, when a tunnel goes down, the traffic that was routed through it quietly falls back to the ordinary internet and the site sees your real address — with no sign that anything changed. With the kill switch on, that traffic goes nowhere until the tunnel is back: pages stop loading, but nothing escapes past the tunnel. Individual routes can override this setting.",
        strictEnforcementOptions: {
          automatic: "Automatic (recommended)",
          enabled: "Always block",
          disabled: "Do not block",
        },
        strictEnforcementHints: {
          automatic:
            "Gatewayless tunnels are protected against leaks while regular gateways remain permissive. Individual routes can override this mode.",
          enabled:
            "An unavailable path is blocked for every interface route so traffic cannot fall back to the main routing table.",
          disabled:
            "Global blocking is disabled. Traffic may fall back to the main routing table unless the route overrides this setting.",
        },
        skipMarkedPacketsLabel: "Skip packets that are already marked",
        skipMarkedPacketsHelp:
          "Other programs on the router mark packets too — that is how they flag traffic they have already routed themselves. With this setting on, keen-pbr leaves those packets alone instead of routing them a second time. Turn it off only if you are sure nothing else on the router marks packets: otherwise one packet ends up under two rules at once, and where it goes is anyone's guess.",
        clearDynamicSetsOnApplyLabel:
          "Clear learned domain addresses on full apply",
        clearDynamicSetsOnApplyHint:
          "Clear dynamic addresses learned by dnsmasq during a full config apply. Disable this to preserve them until TTL expiry and avoid a cold routing start.",
        ipv6EnabledLabel: "Enable IPv6 support",
        ipv6EnabledHint:
          "Install IPv6 routes, firewall rules, and dnsmasq targets. When explicitly disabled, managed dnsmasq suppresses AAAA and SVCB/HTTPS (types 64/65): A records keep working, but HTTP/3 and ECH discovery may be unavailable.",
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
        inboundInterfacesStatusUp: "Up",
        inboundInterfacesStatusDown: "Down",
        inboundInterfacesStatusLoading: "Loading",
        inboundInterfacesStatusMissing: "Missing",
        inboundInterfacesMissingDetail:
          "This interface is saved in config but is not present in the current live interface inventory.",
        internalVpnServersTitle: "Internal VPN servers",
        internalVpnServersDescription:
          "Choose whether traffic and DNS requests from native Keenetic VPN servers with a dedicated system interface are processed by keen-pbr-sb. Switches take effect only after the shared settings form is saved.",
        internalVpnServersEmptyTitle: "No VPN servers found",
        internalVpnServersEmptyDescription:
          "KeeneticOS did not report a supported VPN server with a resolved system interface.",
        internalVpnServersLoadingTitle: "Loading VPN servers",
        internalVpnServersLoadingDescription:
          "Waiting for the KeeneticOS interface inventory. Saved policies will remain unchanged.",
        internalVpnServersUnavailableTitle:
          "VPN server inventory is unavailable",
        internalVpnServersUnavailableDescription:
          "This KeeneticOS version did not provide a supported VPN server inventory. Saved policies remain editable below.",
        internalVpnServersStaleTitle:
          "Showing the last known VPN server configuration",
        internalVpnServersStaleDescription:
          "A fresh KeeneticOS response is temporarily unavailable. Saved policies can be removed, but confirming new servers and changing switches is disabled until the inventory refreshes.",
        internalVpnServersLoadErrorTitle: "Could not load VPN servers",
        internalVpnServersLoadErrorDescription:
          "The KeeneticOS interface inventory is temporarily unavailable. Saved policies remain editable below.",
        internalVpnServersConfirmationTitle:
          "KeeneticOS did not report the WireGuard interface role",
        internalVpnServersConfirmationDescription:
          "Confirm that this is an internal VPN server rather than a client connection. Once confirmed, its clients can be routed through keen-pbr-sb.",
        internalVpnServersConfirmationAction: "Confirm VPN server",
        internalVpnServersProcessLabel: "Through keen-pbr-sb",
        internalVpnServersInheritLabel: "Inherit",
        internalVpnServersStatusUp: "Enabled",
        internalVpnServersStatusDown: "Disabled",
        internalVpnServersStatusMissing: "Missing",
        internalVpnServersStatusUnknown: "Unknown",
        internalVpnServersMissingHint:
          "This policy is saved, but the interface is currently unavailable. It will not be removed automatically.",
        internalVpnServersConfirmationAriaLabel:
          "Confirm {{server}} as an internal VPN server",
        internalVpnServersToggleAriaLabel:
          "Process clients of {{server}} through keen-pbr-sb",
        internalVpnServersInheritAriaLabel:
          "Return {{server}} to the inherited policy",
        internalVpnServicesTitle:
          "L2TP, IKEv1/IKEv2, SSTP and OpenConnect servers",
        internalVpnServicesDescription:
          "These servers have no dedicated Linux interface while idle. keen-pbr-sb safely identifies them by fresh KeeneticOS client pools without treating ordinary LAN traffic as VPN traffic.",
        internalVpnServicesEmptyTitle:
          "No supported server with a client pool found",
        internalVpnServicesEmptyDescription:
          "The current KeeneticOS configuration has no enabled supported server with a valid client address pool.",
        internalVpnServicesLoadingTitle: "Loading KeeneticOS servers",
        internalVpnServicesLoadingDescription:
          "Waiting for the current L2TP, IKEv1/IKEv2, SSTP and OpenConnect configuration. Saved policies remain unchanged.",
        internalVpnServicesUnavailableTitle:
          "Server configuration is unavailable",
        internalVpnServicesUnavailableDescription:
          "KeeneticOS did not provide a fresh authoritative server configuration. New switches are temporarily disabled.",
        internalVpnServicesStaleTitle:
          "Showing the last known server configuration",
        internalVpnServicesStaleDescription:
          "A fresh KeeneticOS response is unavailable. A saved policy can be returned to inherited behavior, but new changes are disabled.",
        internalVpnServicesLoadErrorTitle:
          "Could not load servers with client pools",
        internalVpnServicesLoadErrorDescription:
          "Check keen-pbr-sb access to NDMS. Saved policies are never removed automatically.",
        internalVpnServicesProcessLabel: "Through keen-pbr-sb",
        internalVpnServicesInheritLabel: "Inherit",
        internalVpnServiceNames: {
          l2tp: "L2TP/IPsec VPN server",
          ikev1: "IKEv1/IPsec VPN server",
          ikev2: "IKEv2/IPsec VPN server",
          sstp: "SSTP VPN server",
          openconnect: "OpenConnect VPN server",
        },
        internalVpnServicesStatusEnabled: "Enabled",
        internalVpnServicesStatusDisabled: "Disabled",
        internalVpnServicesStatusMissing: "Missing",
        internalVpnServicesPoolLabel: "Client pool",
        internalVpnServicesBoundInterfaceLabel: "Bound to",
        internalVpnServicesUnavailableHint:
          "Changes are disabled until the server is enabled and its client pool is confirmed by a fresh KeeneticOS response.",
        internalVpnServicesToggleAriaLabel:
          "Process clients of {{server}} through keen-pbr-sb",
        internalVpnServicesInheritAriaLabel:
          "Return {{server}} to the inherited policy",
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
        title: "URL list refresh",
        description:
          "Schedule and global download route chain for remote lists.",
        enabledLabel: "Enable lists autoupdate",
        enabledHint:
          "Automatically download the latest version of your remote lists and update routing when they change.",
        cronLabel: "Refresh schedule",
        cronHintPrefix: "How often to check for updates. Uses cron format. Use",
        cronHintSuffix: "for help.",
        openInGuru: "Open in Crontab Guru",
        routeTitle: "Global download route",
        routeDescription:
          "Used by URL lists by default. An individual list can override this chain.",
        inheritedListsCount:
          "URL lists currently inheriting this chain: {{count}}.",
      },
      softwareUpdate: {
        cancel: "Cancel",
        rollbackConfirmTitle: "Restore the previous keen-pbr-sb version?",
        rollbackConfirmHint:
          "The saved IPK and the configuration that came with it will be installed. The current package stays available to roll forward again.",
        rollbackConfirmAction: "Restore the previous IPK",
        rollbackButton: "One-click rollback",
        rollbackUnavailable: "Appears after a successful managed update",
        rollbackStarting: "Restoring the previous package",
        rollbackFailed: "Could not start the package rollback",
        downloadBackupBefore: "Download a backup before installing",
        progressLabel: "Update progress",
        inProgress: "Update in progress",
        title: "keen-pbr-sb update",
        description:
          "Checks the latest published Release, verifies SHA256SUMS, and installs the IPK while preserving configuration, tunnel and proxy interfaces, and the web account.",
        current: "Installed",
        latest: "Latest release",
        check: "Check for updates",
        checking: "Checking…",
        availableToast: "Update {{version}} is available.",
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
        cachedResult:
          "GitHub is temporarily unavailable. Showing the last saved data.",
        unavailableValue: "check unavailable",
        startFailed: "Could not start the update.",
      },
      advanced: {
        title: "Advanced routing settings",
        description:
          "Advanced settings - only change these if you know what you're doing.",
        reconnectUnmarkedFlowsOnRoutingChangeLabel:
          "Reconnect direct flows after routing changes",
        reconnectUnmarkedFlowsOnRoutingChangeHint:
          "This is the master switch for reconnection after routing changes. When disabled, both regular reconnection of direct flows and enhanced reconnection for the lists below are turned off; old flows wait for conntrack to expire naturally.",
        reconnectOwnedFlowsOnRoutingChangeListsLabel:
          "Lists for enhanced reconnection",
        reconnectOwnedFlowsOnRoutingChangeModeLabel:
          "Enhanced reconnection mode",
        reconnectOwnedFlowsOnRoutingChangeModeOptions: {
          automatic: "Automatic (recommended)",
          manual: "Manual",
        },
        reconnectOwnedFlowsOnRoutingChangeListsHint:
          "WhatsApp/UDP can otherwise keep using the old path. When this setting is not specified, the catalog-installed WhatsApp list is selected automatically. An active call may reconnect once when the route actually switches after a successful route or list change. Only flows owned by the selected lists are terminated: foreign marks and services outside those lists are left untouched, and no global conntrack flush is performed.",
        reconnectOwnedFlowsOnRoutingChangeListsAddAction: "Add a list",
        reconnectOwnedFlowsOnRoutingChangeListsNoAvailable:
          "All available lists have been added",
        reconnectOwnedFlowsOnRoutingChangeListsEmptyTitle: "No lists selected",
        reconnectOwnedFlowsOnRoutingChangeListsEmptyDescription:
          "Select the lists whose connections should use enhanced reconnection.",
        reconnectOwnedFlowsOnRoutingChangeListsRecommended:
          "Automatic recommendation: WhatsApp",
        reconnectOwnedFlowsOnRoutingChangeListsAutomaticStatus:
          "WhatsApp is currently selected automatically. Changing the selection turns it into an explicit setting.",
        reconnectOwnedFlowsOnRoutingChangeListsAutomaticUnavailableStatus:
          "Automatic mode is active, but no catalog-installed WhatsApp list was found.",
        reconnectOwnedFlowsOnRoutingChangeListsOptOutStatus:
          "Explicit opt-out is saved: enhanced reconnection is disabled for all lists.",
        reconnectOwnedFlowsOnRoutingChangeListsExplicitStatus:
          "This is an explicit selection. Removing every list saves an explicit opt-out.",
        reconnectOwnedFlowsOnRoutingChangeListsDisabledStatus:
          "The master switch is off, so enhanced reconnection is disabled for the selected lists.",
        fwmarkStartLabel: "Firewall mark starting value",
        fwmarkStartHint:
          "The starting fwmark assigned to your first route. Each additional route gets the next value in the range.",
        fwmarkMaskLabel: "Firewall mark mask",
        fwmarkMaskHintPrefix:
          "Bitmask defining which bits are used for fwmarks. Must be a continuous block of hex",
        fwmarkMaskHintSuffix: "digits, e.g.",
        tableStartLabel: "IP routing table starting value",
        tableStartHint:
          "The routing table ID assigned to your first route. Each additional route gets the next ID.",
      },
      actions: {
        saving: "Saving...",
        save: "Save",
      },
    },
    dnsServers: {
      sections: {
        servers: {
          title: "Servers",
          description:
            "Who the panel asks for domain addresses. The DNS rules below decide which server is asked about which domain.",
        },
      },
      title: "DNS Servers",
      searchPlaceholder: "Search by name, address or route",
      description: "Upstream DNS servers used for domain name resolution.",
      fallbackSaved: "Fallback DNS order saved to the draft",
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
        outbound: "Route",
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
          dnsRule: "DNS rule “{{name}}” will be deleted.",
          fallback: "Fallback DNS will be changed.",
        },
      },
      bulk: {
        selected: "{{count}} selected",
        delete: "Delete selected",
        enableAction: "Enable",
        disableAction: "Disable",
        confirmSetEnabled:
          "{{action}} the selected rules ({{count}})? The draft will change only after confirmation.",
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
        "Choose a ready-made provider or enter your own DNS server address.",
      editCardTitle: "Edit {{tag}}",
      presets: {
        label: "DNS provider",
        custom: "Custom server",
        includeBackup: "Add the backup server",
        includeBackupHint:
          "A second entry using {{address}} will be created in the same change.",
        backupDisplayName: "{{name}} - backup",
        saveCustom: "Save as a custom template",
        saveCustomHint:
          "The template is stored in the keen-pbr-sb configuration and included in backups.",
      },
      fields: {
        displayName: "Name",
        displayNamePlaceholder: "For example, Home DNS",
        displayNameHint:
          "This name is shown in the interface. The technical identifier is generated automatically.",
        tag: "Name",
        tagHint: "A short name for this server, used in DNS rules.",
        technicalId: "Technical ID",
        technicalIdCreateHint:
          "Generated automatically. Change it only when compatibility with an existing configuration requires it.",
        technicalIdEditHint:
          "Stable identifier used by DNS rules; it cannot be changed after creation.",
        type: "DNS type",
        typeHint:
          "Keenetic reuses the router's current built-in DNS. Plaintext DNS uses a manually entered IP address.",
        typeOptions: {
          keenetic: "Keenetic DNS",
          static: "Plaintext DNS",
        },
        keeneticNotice: {
          legacy:
            "This is an existing Keenetic built-in DNS entry. It is preserved unchanged for compatibility.",
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
        secondaryAddress: "Template backup address",
        secondaryAddressPlaceholder: "For example, 1.0.0.1",
        secondaryAddressHint:
          "Optional IPv4 address. It can be created as a backup DNS server in the same change.",
        detour: "Make requests via route",
        detourEmpty: "Not selected",
        detourPlaceholder: "Optional route tag",
        detourHint:
          "Optional: send DNS queries for this server through a specific route (e.g. a VPN).",
      },
      validation: {
        displayNameRequired: "Enter a readable DNS server name.",
        displayNameTooLong: "The name must not exceed 80 characters.",
        tagRequired: "Name is required.",
        tagUnique: "Name must be unique.",
        typeRequired: "DNS type is required.",
        addressRequired: "Address is required.",
        addressInvalid:
          "Address must be a valid IPv4/IPv6 value with an optional port.",
        templateAddressInvalid:
          "A saved template requires a valid IPv4 address without a port.",
        templateInvalid:
          "The template could not be saved. Check its name, IPv4 addresses, and the number of saved templates.",
      },
      actions: {
        create: "Create DNS server",
        save: "Save DNS server",
      },
    },
    routingRules: {
      title: "Routing rules",
      searchPlaceholder: "Search by name, condition or route",
      reorderPausedBySearch:
        "Reordering is paused while a search is active; clear the query to drag rules again.",
      description:
        "Rules that decide which route handles matching traffic. Evaluated top to bottom.",
      unnamed: "Unnamed",
      actions: {
        reorder: "Drag to reorder",
        addRule: "Add routing rule",
        saveChanges: "Save changes",
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
        enableAction: "enable",
        disableAction: "disable",
        delete: "Delete selected",
        confirmSetEnabled:
          "{{action}} the selected rules ({{count}})? The draft will change only after confirmation.",
        confirmDelete:
          "Delete {{count}} routing rule(s)? You can cancel before saving.",
      },
      empty: {
        title: "No routing rules yet",
        description:
          "Add a routing rule to direct matching traffic to a route.",
      },
      headers: {
        enabled: "On",
        order: "Order",
        orderShort: "#",
        name: "Name",
        criteria: "Match",
        outbound: "Route",
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
      delete: {
        title: "Delete this routing rule?",
        description:
          "The rule stops applying. Lists, routes and DNS rules stay as they are - nothing references a routing rule.",
        confirm: "Delete rule",
      },
      createTitle: "Create routing rule",
      editTitle: "Edit routing rule",
      editCardTitle: "Edit {{name}}",
      description: "This rule directs matching traffic to the specified route.",
      cardDescription:
        "Choose lists and a route, then optionally narrow by protocol, ports, and addresses.",
      simpleCardDescription:
        "Choose a list and a route. That is enough for a working rule; optional match conditions stay in the advanced editor.",
      advancedConditionsPresent:
        "This rule already has additional conditions. They will be preserved; open the advanced editor to review or change them.",
      messages: {
        deleted:
          "Routing rule removed from the draft. Apply the new config to make the change take effect.",
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
        displayNameRequired: "Enter a readable rule name.",
        displayNameTooLong: "The name must not exceed 80 characters.",
        technicalIdRequired: "Technical ID is required.",
        duplicateTechnicalId:
          'A rule with technical ID "{{id}}" already exists.',
        atLeastOneCondition:
          "Specify at least one condition: list, DSCP, source/destination address, or source/destination port.",
        dscpRange: "DSCP must be an integer between 1 and 63.",
        outboundRequired: "A route is required.",
      },
      actions: { create: "Create rule", save: "Save rule" },
      fields: {
        displayName: "Name",
        displayNameHint: "A readable rule name shown throughout the interface.",
        technicalId: "Technical ID",
        technicalIdHint:
          "A stable internal identifier. It is generated automatically and only needs manual control for exact integrations.",
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
        outbound: "Route",
        selectOutbound: "Select route",
        configuredOutbounds: "Configured routes",
        outboundHint: "Which route should handle matching traffic.",
      },
      placeholders: {
        dscp: "46",
        sourcePort: "80,443 or 10000-20000",
        destinationPort: "443 or !53,123",
        sourceAddresses: "192.168.1.10,10.0.0.0/8",
        destinationAddresses: "2001:db8::1 or !203.0.113.0/24",
      },
    },
    rules: {
      title: "Rules",
      description:
        "Where traffic goes and which DNS servers resolve which domains. A single list usually needs both rules.",
      tabs: {
        ariaLabel: "Rule sections",
        routing: "Routing",
        dns: "DNS",
      },
    },
    routesAndTunnels: {
      otherRoutes: {
        title: "Other routes",
        description:
          "Routes without a tunnel of their own: to firmware interfaces or other packages. This block is usually empty.",
      },
      title: "VPN, proxies, groups",
      description:
        "How traffic leaves the router: VPN and proxies, router interfaces, groups and system destinations.",
      tabs: {
        ariaLabel: "VPN, proxy and group sections",
        tunnels: "VPN and proxies",
        interfaces: "Routes",
        failover: "Groups",
        system: "System",
      },
    },
    outbounds: {
      plain: {
        interface: "Traffic leaves through {{name}}",
        urltest: "A group automatically switches to a working tunnel",
        table: "Traffic goes straight through the provider, past the tunnels",
        blackhole: "Connections are not let out",
        ignore: "Traffic passes without changing its route",
      },
      interfaceSubline: "interface {{name}}",
      interfaceMissing: "Interface not found",
      usage: {
        none: "Nothing uses this",
        some: "Lists sent here: {{lists}}, rules: {{rules}}",
      },
      groups: {
        interfaces: "Tunnels and interfaces",
        failover: "Groups",
        system: "System routes",
      },
      split: {
        working: "Working",
        broken: "Not working: interface not found",
        brokenDescription:
          "These routes point at an interface that no longer exists. Traffic will not go through them: the tunnel was deleted or renamed. Open the route and pick an existing interface, or delete the entry.",
      },
      groupsEmpty: {
        interfaces: "No tunnels or interfaces have been added yet.",
        failover: "No groups have been configured yet.",
        system: "No system routes have been configured yet.",
      },
      tabs: {
        ariaLabel: "Route and group sections",
      },
      title: "Routes and groups",
      description:
        "Traffic destinations: tunnels and interfaces, tunnel groups, and system routes.",
      actions: {
        new: "Add route or group",
        newGroup: "Add group",
      },
      bulk: {
        selected: "{{count}} selected",
        delete: "Delete selected",
        confirmDelete:
          "Delete {{count}} route(s) or group(s)? Dependencies are not validated until save.",
      },
      deleteDialog: {
        title: "Delete routes or groups?",
        description:
          "Confirming this operation will make the following changes:",
        confirm: "Delete",
        items: {
          outboundPrefix: "Route",
          outboundSuffix: "will be deleted.",
          dependentOutboundPrefix: "Dependent group",
          dependentOutboundSuffix: "will be deleted.",
          routingRule: "Routing rule “{{name}}” will be removed.",
          ruleDetail: "{{label}}: {{value}}",
          dnsDetour: 'DNS server "{{server}}" will be changed.',
          listDownloadRoutes:
            'List "{{list}}" download routes will be changed.',
          globalListRefreshRoutes:
            "The global URL list refresh routes will be changed.",
          downloadRoutes: "Download routes",
          urltestGroupChanged:
            'Tier #{{group}} in group "{{outbound}}" will be changed.',
          urltestGroupRemoved:
            'Tier #{{group}} in group "{{outbound}}" will be deleted.',
          groupOutbounds: "Group routes",
        },
      },
      empty: {
        title: "No routes or groups yet",
        description: "Add a route or group to start building routing behavior.",
      },
      headers: {
        tag: "Name",
        type: "Source",
        summary: "Details",
        purpose: "What it does",
        memberChain: "Switchover order",
        usedBy: "Used by",
        runtime: "Runtime",
        actions: "Actions",
      },
      summary: {
        interface: "ifname={{value}}",
        gateway4: "gateway4={{value}}",
        gateway6: "gateway6={{value}}",
        table: "table={{value}}",
        urltest: "routes={{value}}",
      },
      messages: {
        missingReference:
          'Route "{{outbound}}" references missing route "{{referenced}}".',
      },
      brokenReferences: {
        title: "The configuration contains broken references",
      },
    },
    outboundUpsert: {
      createTitle: "Create route or group",
      editTitle: "Edit route or group",
      createGroupTitle: "Create group",
      editGroupTitle: "Edit group",
      groupCardDescription:
        "A group combines several tunnels and automatically switches to a working one.",
      editCardTitle: "Edit {{tag}}",
      description:
        "A route can use a network interface, an existing routing table, or a tunnel group that picks a working tunnel by itself.",
      cardDescription: "Configure a route, system action, or group.",
      missing: {
        cardDescription: "The requested route or group could not be found.",
        cardTitle: "Missing route",
        description: "Return to Routes and groups and choose a valid entry.",
        back: "Back to routes",
      },
      actions: { create: "Create route", save: "Save route" },
      common: {
        noExtraFields:
          "No additional fields are required for this type beyond the route tag.",
      },
      fields: {
        displayName: "Name",
        displayNameHint:
          "A readable route or group name shown throughout the interface.",
        technicalId: "Technical ID",
        technicalIdHint:
          "A stable internal identifier used by rules and references. It is generated automatically.",
        tag: "Technical ID",
        tagHint:
          "A unique name for this route. Referenced in traffic rules and groups.",
        type: "Type",
        outboundTypes: "Route types",
        typeOptions: {
          interface: "Interface",
          table: "Routing table",
          urltest: "Tunnel group (auto-select)",
          blackhole: "Blackhole",
          ignore: "Ignore",
        },
      },
      interface: {
        title: "Interface settings",
        description:
          "Set the egress interface and optional IPv4/IPv6 gateways for this route.",
        interface: "Interface",
        interfacePlaceholder: "Select or type an interface",
        interfaceHint: "Egress interface name, e.g. `tun0`, `eth0`, `wg0`.",
        gateway: "Gateway (IPv4)",
        gatewayHint: "Optional IPv4 gateway for this route.",
        gateway6: "Gateway (IPv6)",
        gateway6Hint: "Optional IPv6 gateway for this route.",
      },
      table: {
        title: "Routing table settings",
        description: "Map this route to an existing kernel routing table.",
        field: "Table ID",
        hint: "Kernel routing table ID for this route.",
      },
      blackhole: {
        title: "Blackhole behavior",
        description:
          "Blackhole routes intentionally drop all matching traffic.",
      },
      ignore: {
        title: "Ignore behavior",
        description:
          "Ignore routes pass matching traffic through without policy-based routing changes.",
      },
      urltest: {
        groupsTitle: "Group members",
        groupsDescription:
          "Add routes in preference order. The available-route selection policy is configured below.",
        groupTitle: "Tier {{index}}",
        groupDescription:
          "Tier {{index}} — tunnels in higher tiers are preferred; the next tier is used when the one above is unavailable.",
        groupWeight: "Tier weight",
        groupWeightHint:
          "Lower weights have higher priority. Leave empty to use the default weight of 1.",
        interfaceOutbounds: "Interface routes",
        addOutbound: "Add route",
        noInterfaceOutbounds: "No interface routes found.",
        addInterfaceOutboundsFirst:
          "Add interface routes first so the group has selectable targets.",
        addGroup: "Add tier",
        advancedTitle: "Advanced",
        advancedHint:
          "Availability probing, retries, and the circuit breaker. The defaults suit most setups.",
        probingTitle: "Probing and retries",
        probingDescription: "Availability probing and retries after failures.",
        selectionMode: "Selection mode",
        selectionModeOptions: {
          latency: "Lowest latency",
          priority: "Priority with return to primary",
        },
        selectionModeHints: {
          latency:
            "Selects the fastest healthy route and avoids switching while the difference remains within tolerance.",
          priority:
            "Always uses the first healthy route in the first healthy group and returns to it after recovery.",
        },
        conntrackOnSwitch: "Established connections on switch",
        conntrackOnSwitchOptions: {
          preserve: "Keep on the previous route",
          delete_on_failure: "Reconnect only after failure",
          delete: "Reconnect through the new route",
        },
        conntrackOnSwitchHints: {
          preserve:
            "Existing flows stay on their original path while new flows use the selected route. This is the safest default.",
          delete_on_failure:
            "When the selected exit fails, its flows are removed so applications reconnect through the backup. On return to the preferred exit, existing backup flows are preserved and only new flows use the preferred route.",
          delete:
            "After a successful switch, only flows owned by this group are removed so applications reconnect through the new route.",
        },
        probeUrl: "Probe URL",
        probeUrlHint:
          "The service fetches this URL at the configured interval to verify the interface is alive and measure latency.",
        interval: "Interval (ms)",
        intervalHint: "How often to request the Probe URL (in milliseconds).",
        probeTimeout: "Probe timeout (ms)",
        probeTimeoutHint:
          "Maximum time to wait for one probe attempt to complete.",
        tolerance: "Tolerance (ms)",
        toleranceHint:
          "Do not switch routes unless the latency difference exceeds this value. Prevents flapping.",
        retryAttempts: "Retry attempts",
        retryAttemptsHint:
          "Extra probe attempts before marking the route as failed.",
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
        hint: "Override the global kill-switch setting for this route.",
        default: "Default (as in global config)",
        explanations: {
          default: "Use the global kill-switch setting.",
          enabled:
            "Enabled: if the interface goes down, traffic for this route is blocked instead of leaking directly through the WAN.",
          disabled:
            "Disabled: if the interface goes down, traffic may use another matching route, including the regular WAN.",
        },
      },
      validation: {
        displayNameRequired: "Enter a readable route name.",
        displayNameTooLong: "The name must not exceed 80 characters.",
        tagRequired: "Tag is required.",
        duplicateTag: 'Route tag "{{tag}}" already exists.',
        missingReference:
          'Route "{{outbound}}" references missing route "{{referenced}}".',
      },
    },
    dnsRules: {
      title: "DNS Rules",
      searchPlaceholder: "Search by name, list or DNS server",
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
        enabled: "On",
        name: "Name",
        criteria: "Match",
        serverTag: "DNS server",
        allowDomainRebinding: "Local addresses",
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
      delete: {
        title: "Delete this DNS rule?",
        description:
          "Domains from its lists resolve the usual way again. The lists and DNS servers themselves stay as they are.",
        confirm: "Delete rule",
      },
      createTitle: "Create DNS rule",
      editTitle: "Edit DNS rule",
      editCardTitle: "Edit {{name}}",
      description:
        "This rule defines which DNS server to use for domains in a specific list.",
      cardDescription: "Set the list names and DNS server for this rule.",
      messages: {
        deleted:
          "DNS rule removed from the draft. Apply the new config to make the change take effect.",
        saved: "DNS rule staged. Apply new config to persist it.",
      },
      validation: {
        displayNameRequired: "Enter a readable DNS rule name.",
        displayNameTooLong: "The name must not exceed 80 characters.",
        technicalIdRequired: "Technical ID is required.",
        duplicateTechnicalId:
          'A DNS rule with technical ID "{{id}}" already exists.',
        duplicateId: "DNS rule technical IDs must be unique.",
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
        displayName: "Name",
        displayNameHint:
          "A readable DNS rule name shown throughout the interface.",
        technicalId: "Technical ID",
        technicalIdHint:
          "A stable internal identifier. It is generated automatically and only needs manual control for exact integrations.",
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
      searchPlaceholder: "Search by name, source or rule",
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
        staged:
          "Safe deletion was staged as a draft. Review the changes, then apply them.",
        revisionChanged:
          "The configuration changed in the meantime. The impact was recalculated from fresh data — review it again.",
        referencesLabel: "What to do with dependencies",
        referencesRemoveOption: "Remove references and orphaned rules",
        referencesRemoveHint:
          "References to the deleted lists will be removed. Rules with no other match condition will be deleted so the draft remains valid.",
        referencesReplaceHint:
          "Every reference will be safely rebound to “{{name}}”. Duplicate references will be merged automatically.",
        items: {
          listPrefix: "List",
          listSuffix: "will be deleted.",
          routeRuleRemoved: "Routing rule “{{name}}” will be deleted.",
          routeRuleUpdated: "Routing rule “{{name}}” will be changed.",
          dnsRuleRemoved: "DNS rule “{{name}}” will be deleted.",
          dnsRuleUpdated: "DNS rule “{{name}}” will be changed.",
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
      lastUpdated: "Updated: {{value}}",
      lastRefreshFailed: "Update failed at {{value}}: {{message}}",
      lastRefreshFailedVia:
        "Update failed at {{value}} via {{detour}}: {{message}}",
      technicalId: "Technical ID: {{id}}",
      neverUpdated: "Never updated",
      noStats: "-",
      statsLoaded: "Downloaded",
      statsNotLoaded: "Not downloaded",
      statsNotLoadedFailed:
        "The last download attempt failed - details are in the line under the list name.",
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
        description:
          "A regular template fills in its ready-made URL. Meta, WhatsApp and Telegram open in the catalog so their domain and IP sets are installed together.",
        search: "Search by name or address",
        add: "Select",
        catalogManaged:
          "Related domain and IP sets are installed together through the catalog.",
        openCatalog: "Open catalog",
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
      simpleCardDescription:
        "Enter a readable name and choose the list source. The technical ID is generated automatically.",
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
        description:
          "Set a readable name and choose the source. The internal identifier is generated automatically.",
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
        description:
          "Domains from this list resolve through the selected server. Without one the list uses the primary servers.",
        none: "Not set",
      },
      refreshRoute: {
        modeLabel: "Refresh route",
        modes: {
          inherit: "Use the global chain",
          override: "Set for this list",
        },
        inheritHint:
          "This list uses the global primary and fallback routes from settings.",
        overrideHint:
          "This list uses its own route chain instead of the global one.",
        inheritSummary:
          "Download route: {{chain}}. Change it in the global URL list refresh settings.",
        overrideSummary:
          "Individual download route: {{chain}}. Change it in the advanced editor.",
      },
      quickSetup: {
        title: "Quick rule setup",
        description:
          "Optionally create linked rules together with the list. All changes are saved in one operation.",
        recommendedDescription:
          "For a stable default, simple mode creates dedicated routing and DNS rules for this list.",
        createRouteRule: "Create a routing rule for this list",
        selectOutbound: "Select a route or group",
        createDnsRule: "Create a DNS rule for this list",
        selectDnsServer: "Select a DNS server",
        noDnsServers:
          "Create a DNS server first, then it will become available here.",
        noCompatibleDnsServer:
          "The selected route has no DNS server using the same outbound. Create a compatible DNS server first or use the advanced editor.",
        createDnsServerFromPreset: "DNS server for the selected route",
        createDnsServerFromPresetHint:
          "A compatible plain DNS server will be created with the list and attached to the selected route. Nothing is saved unless the complete setup validates.",
        dnsCreateFailed:
          "Could not prepare a compatible DNS server. Check the route and selected preset.",
        manualHint:
          "Leave the checkboxes off to configure rules manually after creating the list.",
        recommendedHint:
          "Fine tuning and independent rules remain available in the advanced editor.",
        recommendedPlan: {
          title: "Recommended setup",
          description:
            "One list, one routing rule, and one DNS rule are validated and saved together.",
          route: "Route: {{route}}",
          dnsReuse: "DNS: reuse {{dns}}",
          dnsCreate: "DNS: create {{dns}}",
          notSelected: "not selected",
        },
        routeRequired: "Select a route or group for the routing rule.",
        dnsRequired: "Select a DNS server for the DNS rule.",
      },
      fields: {
        displayName: "Display name",
        displayNameHint: "A readable list name shown throughout the interface.",
        technicalId: "Technical ID",
        technicalIdCreateHint:
          "Stable identifier used in rules and references: lowercase Latin letters, digits, and underscores.",
        technicalIdEditHint:
          "Used in rules and references. The technical ID cannot be changed after creation.",
        name: "Name",
        nameHint: "Stable identifier used in rules and references.",
        ttlMs: "IP cache duration (ms)",
        ttlMsHint:
          "How long to keep resolved IPs in the ipset. `0` = no timeout.",
        detour: "Make requests via route",
        detourEmpty: "Not selected",
        detourPlaceholder: "Optional route tag",
        detourHint:
          "Optional route to use when downloading this list from a remote URL.",
        fallbackDetours: "Fallback download routes",
        fallbackDetoursAdd: "Add a fallback route",
        fallbackDetoursEmpty: "No fallback routes are available",
        fallbackDetoursLimit: "Up to three fallback routes can be selected",
        fallbackDetoursPlaceholder: "No fallback routes selected",
        fallbackDetoursPlaceholderDescription:
          "They are tried in order if the download fails.",
        fallbackDetoursHint:
          "Used only after a network or HTTP failure on the primary route. A direct connection is never added automatically.",
        url: "Remote URL",
        urlHint:
          "Optional: a plain-text list or an `.srs` file in format version 1-5. It is merged with the other content; sing-box is not required for `.srs`.",
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
        displayNameRequired: "Enter a readable list name.",
        displayNameTooLong: "The name must not exceed 80 characters.",
        sourceRequired: "Fill in the selected source so the list can be used.",
        nameRequired: "Technical ID is required.",
        duplicateName: "A list with this technical ID already exists.",
        invalidTtl: "TTL must be a non-negative integer.",
        refreshDetourRequired:
          "Select a primary route for the individual refresh chain.",
      },
    },
  },
} as const

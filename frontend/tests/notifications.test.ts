import { describe, expect, test } from "bun:test"

import { collectNotices } from "@/components/layout/notifications"

const t = (key: string, options?: Record<string, unknown>) =>
  `${key}:${String(options?.version ?? "")}`

describe("notification collector", () => {
  test("keeps the routing failure but not the subsequent routine recovery notice", () => {
    const failure =
      "Runtime state running -> broken: configuration generation terminal is unknown"
    const notices = collectNotices(
      [
        `2026-09-10 05:19:14.270 [W] ${failure}`,
        "2026-09-10 05:19:56.359 [W] Runtime state broken -> starting: runtime start requested",
        "2026-09-10 05:19:57.000 [I] Runtime state starting -> running: runtime start complete",
      ],
      undefined,
      undefined,
      undefined,
      ["failure", "recovery", "started"],
      new Set(),
      t
    )
    expect(notices).toHaveLength(1)
    expect(notices[0]).toMatchObject({
      id: "failure",
      level: "warning",
      details: failure,
      text: "notifications.messages.runtimeApplyUnverified:",
      timestamp: "2026-09-10 05:19:14.270",
    })
  })

  test("does not hide a failed recovery or an unknown transition reason", () => {
    const details = [
      "Runtime state starting -> broken: runtime start failed",
      "Runtime state broken -> starting: unexpected recovery condition",
      "Worker failed: Runtime state broken -> starting: runtime start requested",
      "Runtime state running -> broken: runtime start requested",
    ]
    const notices = collectNotices(
      details.map(
        (text, index) => `2026-09-10 05:20:0${index}.000 [E] ${text}`
      ),
      undefined,
      undefined,
      undefined,
      [],
      new Set(),
      t
    )
    expect(notices).toHaveLength(details.length)
    expect(notices.map((notice) => notice.details)).toEqual(
      [...details].reverse()
    )
    expect(notices.every((notice) => notice.level === "error")).toBe(true)
  })

  test("routine startup and verified shutdown stay in the journal only", () => {
    const notices = collectNotices(
      [
        "2026-09-10 05:19:56.359 [W] Runtime state broken -> starting: cold-boot recovery attempt admitted",
        "2026-09-10 05:19:57.000 [W] Runtime state broken -> running: runtime start complete",
        "2026-09-10 05:19:58.000 [W] Runtime state shutting_down -> stopped: daemon shutdown cleanup verified",
      ],
      undefined,
      undefined,
      undefined,
      [],
      new Set(),
      t
    )
    expect(notices).toEqual([])
  })

  test("keeps an exact dismissed record hidden when its tail index changes", () => {
    const incident = "2026-09-05 15:16:00.000 [E] Managed route repair failed"
    const lines = ["2026-09-05 15:15:00.000 [I] Background check", incident]
    const dismissed = new Set(["log-incident"])
    const beforeTailMoved = collectNotices(
      lines,
      undefined,
      undefined,
      undefined,
      ["log-background", "log-incident"],
      dismissed,
      t
    )
    const afterTailMoved = collectNotices(
      [incident],
      undefined,
      undefined,
      undefined,
      ["log-incident"],
      dismissed,
      t
    )

    expect(beforeTailMoved).toEqual([])
    expect(afterTailMoved).toEqual([])
  })

  test("shows a newly recorded identical message with a different exact ID", () => {
    const incident = "2026-09-05 15:16:00.000 [E] Managed route repair failed"
    const notices = collectNotices(
      [incident, incident],
      undefined,
      undefined,
      undefined,
      ["log-dismissed", "log-new"],
      new Set(["log-dismissed"]),
      t
    )

    expect(notices).toHaveLength(1)
    expect(notices[0]?.id).toBe("log-new")
    expect(notices[0]?.details).toBe("Managed route repair failed")
  })

  test("hides the resolved Keenetic remote-access compatibility incident only", () => {
    const notices = collectNotices(
      [
        "2026-08-12 22:15:19.756 [E] Cannot reconcile remote-access firewall state: remote access is unavailable with the Keenetic authentication provider because router credentials would traverse plaintext WAN HTTP",
        "2026-08-12 22:15:20.000 [E] Cannot reconcile remote-access firewall state: remote access is disabled, but owned firewall rules could not be removed and verified",
      ],
      undefined,
      undefined,
      undefined,
      [],
      new Set(),
      t
    )

    expect(notices).toHaveLength(1)
    expect(notices[0]?.details).toContain(
      "owned firewall rules could not be removed and verified"
    )
  })

  test("does not turn a successful managed-route repair into a warning", () => {
    const notices = collectNotices(
      [
        "2026-07-25 21:00:00.000 [I] Restoring vanished managed route (dst=default, table=153, iface=mooo_vless, gw=(none), metric=1, protocol=186)",
        "2026-07-25 21:00:01.000 [W] Managed route repair failed",
      ],
      undefined,
      undefined,
      undefined,
      [],
      new Set(),
      t
    )

    expect(notices).toHaveLength(1)
    expect(notices[0]?.details).toBe("Managed route repair failed")
  })

  test("keeps internal firewall recovery details out of the notification bell", () => {
    const notices = collectNotices(
      [
        "2026-07-27 18:24:12.600 [E] safe_exec_pipe_failed cmd=iptables-restore --noflush --counters exit_code=1 duration_ms=29",
        "2026-07-27 18:24:12.601 [E] safe_exec_pipe_input cmd=iptables-restore --noflush --counters input_bytes=8358 preview_bytes=4096 truncated=true:",
        "2026-07-27 18:24:13.000 [W] Best-effort conntrack cleanup failed while stopping routing for mark 0x20000/0xff0000",
        "2026-07-27 18:24:14.000 [E] Runtime iproute and firewall refresh failed: failed to inspect live iptables dispatcher KeenPbrTable",
        "2026-07-27 18:24:15.000 [W] Firewall retry 2 failed: line 103 failed. Trying again.",
        "2026-07-27 18:24:16.000 [W] Urltest 'awg_bound' switch to 'techcorner_awg' was rolled back; the next probe may retry it",
        "2026-07-27 18:25:00.000 [E] Giving up on applying firewall rules after 6 retries: final failure",
      ],
      undefined,
      undefined,
      undefined,
      [],
      new Set(),
      t
    )

    expect(notices).toHaveLength(1)
    expect(notices[0]?.details).toBe(
      "Giving up on applying firewall rules after 6 retries: final failure"
    )
  })

  test("keeps a permanent historical firewall failure actionable", () => {
    const notices = collectNotices(
      [
        "2026-07-27 18:30:00.000 [E] Runtime iproute and firewall refresh failed: iptables-restore: line 41 failed (rule: -A malformed)",
      ],
      undefined,
      undefined,
      undefined,
      [],
      new Set(),
      t
    )

    expect(notices).toHaveLength(1)
    expect(notices[0]?.details).toContain("line 41 failed")
  })

  test("keeps exact-domain-only SRS mapping in the journal", () => {
    const notices = collectNotices(
      [
        "2026-07-29 12:00:00.000 [W] List 'github_2': SRS import is lossy: mapped 30 exact domain(s) to keen-pbr root-and-subdomain semantics",
        "2026-07-29 12:00:01.000 [W] List 'broken': failed to refresh https://example.test/broken.srs: SRS contains no safely representable domain, domain suffix or IP/CIDR entries",
      ],
      undefined,
      undefined,
      undefined,
      [],
      new Set(),
      t
    )

    expect(notices).toHaveLength(1)
    expect(notices[0]?.details).toContain("failed to refresh")
  })

  test("hides bounded SRS narrowing but keeps materially lossy conversion visible", () => {
    const notices = collectNotices(
      [
        "2026-07-29 12:00:00.000 [W] List 'geosite_category_ai_nocn': SRS import is lossy: mapped 28 exact domain(s) to keen-pbr root-and-subdomain semantics; skipped 1 unsupported condition(s)",
        "2026-07-29 12:00:01.000 [W] List 'unsupported': SRS import is lossy: skipped 2 unsupported condition(s)",
        "2026-07-29 12:00:02.000 [W] List 'rules': SRS import is lossy: skipped 3 rule(s), including 1 inverted rule(s)",
        "2026-07-29 12:00:03.000 [W] List 'domains': SRS import is lossy: skipped 4 invalid domain value(s)",
      ],
      undefined,
      undefined,
      undefined,
      [],
      new Set(),
      t
    )

    expect(notices.map((notice) => notice.details)).toEqual([
      "List 'domains': SRS import is lossy: skipped 4 invalid domain value(s)",
      "List 'rules': SRS import is lossy: skipped 3 rule(s), including 1 inverted rule(s)",
    ])
  })

  test("adds a stable version-specific nfqws2 update notice", () => {
    const notices = collectNotices(
      [],
      undefined,
      {
        ok: true,
        installed: true,
        current: "1.0.2",
        latest: "v1.1.0",
        available: true,
      },
      undefined,
      [],
      new Set(),
      t
    )

    expect(notices).toEqual([
      {
        id: "nfqws-update-v1.1.0",
        level: "info",
        text: "notifications.nfqwsUpdateAvailable:v1.1.0",
      },
    ])
  })

  test("does not announce updates when nfqws2 is not installed", () => {
    const notices = collectNotices(
      [],
      undefined,
      {
        ok: true,
        installed: false,
        current: "",
        latest: "",
        available: false,
      },
      undefined,
      [],
      new Set(),
      t
    )

    expect(notices).toEqual([])
  })

  test("keeps a dismissed version hidden and shows a newer version", () => {
    const dismissed = new Set(["nfqws-update-v1.1.0"])
    const hidden = collectNotices(
      [],
      undefined,
      {
        ok: true,
        installed: true,
        current: "1.0.2",
        latest: "v1.1.0",
        available: true,
      },
      undefined,
      [],
      dismissed,
      t
    )
    const newer = collectNotices(
      [],
      undefined,
      {
        ok: true,
        installed: true,
        current: "1.0.2",
        latest: "v1.2.0",
        available: true,
      },
      undefined,
      [],
      dismissed,
      t
    )

    expect(hidden).toEqual([])
    expect(newer[0]?.id).toBe("nfqws-update-v1.2.0")
  })

  test("coalesces repeated current Meta incidents without declaring recovery", () => {
    const notices = collectNotices(
      [
        "2026-08-27 21:06:07.355 [E] Meta/WhatsApp UDP/443 policy state is degraded: delayed firewall COMMIT outcome is ambiguous; exact Meta cleanup authority was discarded. The service will perform a bounded recovery without broadening the affected traffic scope.",
        "2026-08-27 21:53:45.503 [E] Meta/WhatsApp UDP/443 policy state is degraded: balanced mode could not verify absence of owned UDP/443 artifacts after delayed publication. The service will perform a bounded recovery without broadening the affected traffic scope.",
      ],
      undefined,
      undefined,
      undefined,
      [],
      new Set(),
      t
    )

    expect(notices).toHaveLength(1)
    expect(notices[0]?.timestamp).toBe("2026-08-27 21:53:45.503")
    expect(notices[0]?.details).toContain("balanced mode")
  })

  test("coalesces repeated current PPE incidents without inferring recovery", () => {
    const notices = collectNotices(
      [
        "2026-08-27 16:21:16.717 [W] PPE de-offload reconciliation degraded: could not inspect the IPv4 PPE de-offload graph",
        "2026-08-27 21:53:47.825 [W] PPE de-offload reconciliation degraded: could not inspect the IPv4 PPE de-offload graph",
      ],
      undefined,
      undefined,
      undefined,
      [],
      new Set(),
      t
    )

    expect(notices).toHaveLength(1)
    expect(notices[0]?.timestamp).toBe("2026-08-27 21:53:47.825")
  })

  test("does not compare router log time with browser-local health time", () => {
    const line =
      "2026-08-27 21:53:47.825 [W] PPE de-offload reconciliation degraded: could not inspect the IPv4 PPE de-offload graph"
    const notices = collectNotices(
      [line],
      undefined,
      undefined,
      undefined,
      [],
      new Set(),
      t
    )

    expect(notices).toHaveLength(1)
    expect(notices[0]?.timestamp).toBe("2026-08-27 21:53:47.825")
  })

  test("drops prior-process incidents only for the matching running build", () => {
    const lines = [
      "2026-08-27 11:10:54.565 [E] Meta/WhatsApp UDP/443 policy state is degraded: delayed firewall COMMIT outcome is ambiguous; exact Meta cleanup authority was discarded. The service will perform a bounded recovery without broadening the affected traffic scope.",
      "2026-08-27 12:19:21.298 keen-pbr 3.3.0 (build 20260827080953, commit 89118c8653b9) starting, log file: /opt/var/log/keen-pbr.log",
    ]
    const matching = collectNotices(
      lines,
      undefined,
      undefined,
      undefined,
      [],
      new Set(),
      t,
      {
        service: {
          build: "20260827080953",
          commit: "89118c8653b9",
          runtime_state: "running",
        },
      }
    )
    const wrongCommit = collectNotices(
      lines,
      undefined,
      undefined,
      undefined,
      [],
      new Set(),
      t,
      {
        service: {
          build: "20260827080953",
          commit: "different0000",
          runtime_state: "running",
        },
      }
    )

    expect(matching).toHaveLength(0)
    expect(wrongCommit).toHaveLength(1)
  })

  test("does not hide a current Meta incident after the matching restart", () => {
    const notices = collectNotices(
      [
        "2026-08-27 12:19:21.298 keen-pbr 3.3.0 (build 20260827080953, commit 89118c8653b9) starting, log file: /opt/var/log/keen-pbr.log",
        "2026-08-27 21:53:45.503 [E] Meta/WhatsApp UDP/443 policy state is degraded: balanced mode could not verify absence of owned UDP/443 artifacts after delayed publication. The service will perform a bounded recovery without broadening the affected traffic scope.",
      ],
      undefined,
      undefined,
      undefined,
      [],
      new Set(),
      t,
      {
        service: {
          build: "20260827080953",
          commit: "89118c8653b9",
          runtime_state: "running",
        },
      }
    )

    expect(notices).toHaveLength(1)
    expect(notices[0]?.timestamp).toBe("2026-08-27 21:53:45.503")
  })
})

describe("list refresh notices follow the daemon, not the journal", () => {
  const failedNight = [
    "2026-08-16 04:00:39.746 [W] List 'porn': failed to refresh https://example.invalid/porn.srs: Could not resolve host: example.invalid",
    "2026-08-16 04:00:41.147 [W] Lists refresh (autoupdate): failed list(s): ads, porn",
  ]

  test("a list the daemon now reports as healthy stops accusing", () => {
    const notices = collectNotices(
      failedNight,
      undefined,
      undefined,
      { ads: { last_updated: "2026-08-18T01:00:00Z" }, porn: {} },
      [],
      new Set(),
      t
    )

    expect(notices).toHaveLength(0)
  })

  test("a list that is still broken keeps its notice", () => {
    const notices = collectNotices(
      failedNight,
      undefined,
      undefined,
      {
        ads: {},
        porn: { last_error: "Could not resolve host: example.invalid" },
      },
      [],
      new Set(),
      t
    )

    expect(notices).toHaveLength(2)
  })

  test("one still-broken list keeps the summary that names it", () => {
    const notices = collectNotices(
      [
        "2026-08-16 04:00:41.147 [W] Lists refresh: failed to refresh list(s): ads, porn",
      ],
      undefined,
      undefined,
      { ads: {}, porn: { last_error: "boom" } },
      [],
      new Set(),
      t
    )

    expect(notices).toHaveLength(1)
  })

  test("a list the daemon does not report is not assumed to have recovered", () => {
    const notices = collectNotices(
      [
        "2026-08-16 04:00:39.746 [W] List 'gone': failed to refresh https://example.invalid/x: boom",
      ],
      undefined,
      undefined,
      {},
      [],
      new Set(),
      t
    )

    expect(notices).toHaveLength(1)
  })

  test("a failure that could not record itself is never cleared by an empty record", () => {
    // This warning fires exactly when last_error could not be written, so an
    // absent error is its symptom rather than evidence of recovery.
    const notices = collectNotices(
      [
        "2026-08-16 04:00:39.746 [W] List 'ads': could not persist refresh failure status: disk full",
      ],
      undefined,
      undefined,
      { ads: {} },
      [],
      new Set(),
      t
    )

    expect(notices).toHaveLength(1)
  })
})

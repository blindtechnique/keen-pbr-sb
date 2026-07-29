import { describe, expect, test } from "bun:test"

import { collectNotices } from "@/components/layout/notifications"

const t = (key: string, options?: Record<string, unknown>) =>
  `${key}:${String(options?.version ?? "")}`

describe("notification collector", () => {
  test("does not turn a successful managed-route repair into a warning", () => {
    const notices = collectNotices(
      [
        "2026-07-25 21:00:00.000 [I] Restoring vanished managed route (dst=default, table=153, iface=mooo_vless, gw=(none), metric=1, protocol=186)",
        "2026-07-25 21:00:01.000 [W] Managed route repair failed",
      ],
      undefined,
      undefined,
      0,
      new Set(),
      t
    )

    expect(notices).toHaveLength(1)
    expect(notices[0]?.text).toBe("Managed route repair failed")
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
      0,
      new Set(),
      t
    )

    expect(notices).toHaveLength(1)
    expect(notices[0]?.text).toBe(
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
      0,
      new Set(),
      t
    )

    expect(notices).toHaveLength(1)
    expect(notices[0]?.text).toContain("line 41 failed")
  })

  test("keeps exact-domain-only SRS mapping in the journal", () => {
    const notices = collectNotices(
      [
        "2026-07-29 12:00:00.000 [W] List 'github_2': SRS import is lossy: mapped 30 exact domain(s) to keen-pbr root-and-subdomain semantics",
        "2026-07-29 12:00:01.000 [W] List 'broken': failed to refresh https://example.test/broken.srs: SRS contains no safely representable domain, domain suffix or IP/CIDR entries",
      ],
      undefined,
      undefined,
      0,
      new Set(),
      t
    )

    expect(notices).toHaveLength(1)
    expect(notices[0]?.text).toContain("failed to refresh")
  })

  test("keeps materially lossy SRS conversion visible", () => {
    const notices = collectNotices(
      [
        "2026-07-29 12:00:00.000 [W] List 'geosite_category_ai_nocn': SRS import is lossy: mapped 28 exact domain(s) to keen-pbr root-and-subdomain semantics; skipped 1 unsupported condition(s)",
        "2026-07-29 12:00:01.000 [W] List 'unsupported': SRS import is lossy: skipped 2 unsupported condition(s)",
        "2026-07-29 12:00:02.000 [W] List 'rules': SRS import is lossy: skipped 3 rule(s), including 1 inverted rule(s)",
        "2026-07-29 12:00:03.000 [W] List 'domains': SRS import is lossy: skipped 4 invalid domain value(s)",
      ],
      undefined,
      undefined,
      0,
      new Set(),
      t
    )

    expect(notices.map((notice) => notice.text)).toEqual([
      "List 'domains': SRS import is lossy: skipped 4 invalid domain value(s)",
      "List 'rules': SRS import is lossy: skipped 3 rule(s), including 1 inverted rule(s)",
      "List 'unsupported': SRS import is lossy: skipped 2 unsupported condition(s)",
      "List 'geosite_category_ai_nocn': SRS import is lossy: mapped 28 exact domain(s) to keen-pbr root-and-subdomain semantics; skipped 1 unsupported condition(s)",
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
      0,
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
      0,
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
      0,
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
      0,
      dismissed,
      t
    )

    expect(hidden).toEqual([])
    expect(newer[0]?.id).toBe("nfqws-update-v1.2.0")
  })
})

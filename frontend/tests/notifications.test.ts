import { describe, expect, test } from "bun:test"

import { collectNotices } from "@/components/layout/notifications"

const t = (key: string, options?: Record<string, unknown>) =>
  `${key}:${String(options?.version ?? "")}`

describe("notification collector", () => {
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

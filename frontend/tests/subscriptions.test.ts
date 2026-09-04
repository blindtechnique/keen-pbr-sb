import { describe, expect, test } from "bun:test"
import { readFileSync } from "node:fs"
import type { SavedSubscription } from "@/api/generated/model"
import {
  subscriptionBytes,
  subscriptionUsage,
} from "@/components/transports/subscription-usage"

const base: SavedSubscription = {
  id: "one",
  name: "Plan",
  source_host: "example.com",
  transport_tags: [],
  checked_at: 1,
}
describe("subscription metadata presentation", () => {
  test("missing counters or limits are unknown, not zero or unlimited", () => {
    expect(subscriptionUsage(base).remaining).toBeUndefined()
    expect(
      subscriptionUsage({ ...base, total_bytes: 100 }).remaining
    ).toBeUndefined()
    expect(
      subscriptionUsage({ ...base, upload_bytes: 5, download_bytes: 10 }).used
    ).toBe(15)
    expect(subscriptionUsage(base).expired).toBe(false)
  })
  test("remaining traffic is clamped at zero and percentage at 100", () => {
    const result = subscriptionUsage({
      ...base,
      upload_bytes: 20,
      download_bytes: 100,
      total_bytes: 100,
    })
    expect(result.remaining).toBe(0)
    expect(result.percent).toBe(100)
  })
  test("expiry uses provider date with no guessed duration", () => {
    expect(subscriptionUsage({ ...base, expires_at: 86401 }, 1000).days).toBe(1)
    expect(
      subscriptionUsage({ ...base, expires_at: 100 }, 100000).expired
    ).toBe(true)
    expect(subscriptionUsage(base).days).toBeUndefined()
  })
  test("formats actual byte units for the selected language", () => {
    expect(subscriptionBytes(1e9, "en")).toContain("1")
    expect(subscriptionBytes(1e9, "ru")).not.toBe(subscriptionBytes(1e9, "en"))
  })
  test("ordinary nfqws upgrade does not implicitly export a secret archive", () => {
    const source = readFileSync(
      new URL("../src/pages/nfqws-page.tsx", import.meta.url),
      "utf8"
    )
    expect(source).toContain(
      "[downloadUpgradeBackup, setDownloadUpgradeBackup] = useState(false)"
    )
    expect(source).toContain('nfqwsAction({ action: "upgrade" })')
  })
})

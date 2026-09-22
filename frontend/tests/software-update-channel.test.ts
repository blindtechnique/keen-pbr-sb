import { expect, test } from "bun:test"
import { softwareUpdateRequest } from "@/components/settings/software-update-channel"
import type { SystemUpdateStatus } from "@/api/generated/model"

const ready: Partial<SystemUpdateStatus> = {
  channel: "alpha",
  installed_channel: "stable",
  installable: true,
  release_tag: "alpha-123-1",
  latest: "v3.3.2-20260919120000",
}
test("installation confirms an exact channel, tag and full package timestamp", () => {
  expect(softwareUpdateRequest(ready)).toEqual({
    channel: "alpha",
    release_tag: "alpha-123-1",
    version: "v3.3.2-20260919120000",
  })
})
test("saving a channel without a release never enables installation", () => {
  expect(softwareUpdateRequest({ channel: "alpha" })).toBeNull()
  expect(softwareUpdateRequest(null)).toBeNull()
})
test("missing metadata, downgrade, network failure, and obsolete channels fail closed", () => {
  for (const change of [
    { channel: "next" },
    { channel: "" },
    { latest: "" },
    { release_tag: "" },
    { installable: false },
    { current_ahead: true },
    { running: true },
    { check_error: "timeout" },
  ])
    expect(softwareUpdateRequest({ ...ready, ...change })).toBeNull()
})
test("same-version explicit channel switch need not be advertised as a newer version", () => {
  expect(
    softwareUpdateRequest({ ...ready, available: false, channel_change: true })
  ).not.toBeNull()
})

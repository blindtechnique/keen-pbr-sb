import { expect, test } from "bun:test"

test("logging toggle and verbosity are disabled while their captured draft is saving", async () => {
  const source = await Bun.file(
    new URL(
      "../src/components/settings/logging-settings-card.tsx",
      import.meta.url
    )
  ).text()
  const toggle = source.match(/<Switch\s[\s\S]*?id="logging-enabled"/u)?.[0]
  const level = source.match(
    /<Select\s[\s\S]*?<SelectTrigger id="logging-level"/u
  )?.[0]
  expect(toggle).toContain("disabled={saveMutation.isPending}")
  expect(level).toContain("disabled={!fileEnabled || saveMutation.isPending}")
})

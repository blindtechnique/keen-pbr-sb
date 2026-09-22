import { expect, test } from "bun:test"
import { createInstance } from "i18next"
import { I18nextProvider } from "react-i18next"
import { renderToStaticMarkup } from "react-dom/server"
import { UpdateChannelControl } from "@/components/settings/update-channel-control"
import { ruTranslation } from "@/i18n/ru"

test("channel choice is named, warns about Alpha and cannot install on render", async () => {
  const i18n = createInstance()
  await i18n.init({
    lng: "ru",
    resources: { ru: { translation: ruTranslation } },
  })
  let actions = 0
  const html = renderToStaticMarkup(
    <I18nextProvider i18n={i18n}>
      <UpdateChannelControl
        channel="alpha"
        disabled={false}
        saving={false}
        onSaving={() => actions++}
        onSaved={() => actions++}
      />
    </I18nextProvider>
  )
  expect(html).toContain('id="software-update-channel"')
  expect(html).toContain('aria-describedby="software-update-channel-hint"')
  expect(html).toContain("Alpha — тестовые сборки")
  expect(html).toContain("не устанавливает обновление")
  expect(html).toContain("Сохранить канал")
  expect(html).not.toContain("Установить обновление")
  expect(actions).toBe(0)
})

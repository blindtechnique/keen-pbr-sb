# Сайт проекта keen-pbr-sb

Статический сайт для GitHub Pages. Ветка `gh-pages`, сборка не требуется —
это готовые файлы, которые Pages отдаёт как есть.

```
index.html            весь сайт: разметка и содержимое
assets/style.css      оформление, светлая и тёмная темы
assets/app.js         тема, вкладки галереи, лайтбокс, копирование команды
assets/img/*.webp     скриншоты панели (обезличенные)
assets/fonts/*.woff2  Roboto, латиница и кириллица, 400/500/700
assets/logo.png       логотип
.nojekyll             отключает обработку Jekyll
```

## Публикация

Из корня основного репозитория, где лежит распакованный `site/`:

```sh
git switch --orphan gh-pages
git rm -rf --cached . >/dev/null 2>&1 || true
cp -r site/. .
git add -A
git commit -m "docs(site): страница проекта"
git push -u origin gh-pages
```

Затем в GitHub: **Settings → Pages → Build and deployment**,
Source — `Deploy from a branch`, Branch — `gh-pages`, папка `/ (root)`.
Через минуту сайт будет доступен по адресу
`https://blindtechnique.github.io/keen-pbr-sb/`.

## Обновление

Правится `index.html` — весь текст лежит там же, где разметка.
Скриншоты кладутся в `assets/img/` в формате WebP шириной 1800 px.

## Скриншоты

Сделаны на рабочей установке. Имена туннелей, маршрутов, списков и локальный
IP заменены на условные средствами обработки изображения — в самой панели
ничего не менялось.

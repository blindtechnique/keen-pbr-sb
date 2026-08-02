#!/bin/sh
# Публикация сайта в ветку gh-pages.
# Запускать из корня репозитория keen-pbr-sb, рядом должна лежать папка site/.
set -eu

test -f site/index.html || { echo "Не вижу site/index.html — запустите из корня репозитория"; exit 1; }
git rev-parse --git-dir >/dev/null 2>&1 || { echo "Это не git-репозиторий"; exit 1; }

BRANCH=gh-pages
TMP=$(mktemp -d)
cp -r site/. "$TMP/"

CUR=$(git rev-parse --abbrev-ref HEAD)
if git show-ref --verify --quiet "refs/heads/$BRANCH"; then
  git switch "$BRANCH"
  git rm -rq . 2>/dev/null || true
else
  git switch --orphan "$BRANCH"
  git rm -rq --cached . 2>/dev/null || true
  find . -maxdepth 1 ! -name . ! -name .git -exec rm -rf {} +
fi

cp -r "$TMP/." .
rm -rf "$TMP"
git add -A
git commit -m "docs(site): обновление страницы проекта" || echo "Изменений нет"
echo
echo "Готово локально. Отправить: git push -u origin $BRANCH"
echo "Вернуться в рабочую ветку: git switch $CUR"

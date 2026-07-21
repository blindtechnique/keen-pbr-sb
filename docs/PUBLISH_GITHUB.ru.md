# Публикация keen-pbr-sb на GitHub с Windows 11

Эта инструкция рассчитана на репозиторий `blindtechnique/keen-pbr-sb`, в котором уже опубликована предыдущая версия. GitHub Actions не нужны: исходники отправляются через Git, а готовый IPK прикрепляется к Release вручную.

## Что подготовлено

- чистая папка исходников `keen-pbr-sb-source-v3.0.7-sb.4-final`;
- архив этой папки для резервной копии;
- готовый пакет `keen-pbr_3.0.7-4_keenetic_aarch64-3.10.ipk`;
- файл контрольных сумм `SHA256SUMS`;
- тег выпуска `v3.0.7-sb.4`.

Не добавляйте в репозиторий каталог `build`, `.cache`, `node_modules`, готовые IPK и ZIP-архивы. IPK и `SHA256SUMS` загружаются только в GitHub Release.

## 1. Сделать резервную копию

1. Закройте редакторы, которые могут менять файлы проекта.
2. Не удаляйте старую папку с проектом.
3. Сохраните подготовленный ZIP отдельно. Он нужен только как локальная страховка.

## 2. Проверить Git

Откройте PowerShell: нажмите `Win`, напишите `PowerShell`, запустите найденное приложение.

Проверьте Git:

```powershell
git --version
```

Если Windows пишет, что команда не найдена, закройте PowerShell, переустановите Git for Windows с настройками по умолчанию и откройте новое окно PowerShell.

Один раз задайте имя и e-mail автора коммитов:

```powershell
git config --global user.name "blindtechnique"
git config --global user.email "ВАШ_EMAIL_ОТ_GITHUB"
```

Вместо текста `ВАШ_EMAIL_ОТ_GITHUB` укажите адрес из GitHub → Settings → Emails. Можно использовать приватный адрес вида `...@users.noreply.github.com`.

## 3. Клонировать текущий репозиторий

Работайте в новой папке. Так уже опубликованная версия и история Git не потеряются.

```powershell
cd "$HOME\Documents"
git clone https://github.com/blindtechnique/keen-pbr-sb.git keen-pbr-sb-publish
cd keen-pbr-sb-publish
git status
```

Ожидаемый результат последней команды: ветка `main`, рабочая папка чистая.

Сразу создайте локальную резервную ветку предыдущего состояния:

```powershell
git branch backup-before-v3.0.7-sb.4
```

Эта команда ничего не публикует и не меняет файлы.

## 4. Наложить новые исходники поверх клона

1. Откройте в Проводнике папку `keen-pbr-sb-source-v3.0.7-sb.4-final`.
2. Выделите всё внутри неё (`Ctrl+A`) и скопируйте (`Ctrl+C`).
3. Откройте папку `%USERPROFILE%\Documents\keen-pbr-sb-publish`.
4. Вставьте файлы (`Ctrl+V`) и согласитесь заменить существующие.
5. Не удаляйте скрытую папку `.git` внутри `keen-pbr-sb-publish`. В подготовленных исходниках её нет, поэтому обычное копирование её не затронет.

Если в старой версии репозитория остались файлы, которых нет в новой папке, удалите только заведомо устаревшие файлы проекта. Не удаляйте `.git`.

## 5. Проверить, что попадёт на GitHub

Вернитесь в PowerShell:

```powershell
cd "$HOME\Documents\keen-pbr-sb-publish"
git status --short
```

В списке не должно быть:

- `.env`, паролей, приватных SSH-ключей;
- `auth.json` и ваших рабочих конфигураций роутера;
- каталогов `build`, `.cache`, `node_modules`;
- IPK и ZIP-файлов;
- `.github/workflows` — в этом выпуске Actions намеренно не используются.

Проверьте изменения подробнее:

```powershell
git diff --stat
git diff -- README.md
```

README.md должен быть русским основным описанием keen-pbr-sb.

## 6. Создать коммит

Добавьте изменения:

```powershell
git add --all
git status --short
```

Ещё раз просмотрите список. Если там нет секретов и лишних сборочных файлов, создайте коммит:

```powershell
git commit -m "release: keen-pbr-sb v3.0.7-sb.4"
```

## 7. Отправить ветку main

Сначала получите актуальное состояние GitHub и убедитесь, что за время подготовки никто не изменил репозиторий:

```powershell
git pull --rebase origin main
```

Если команда завершилась успешно:

```powershell
git push origin main
```

GitHub может открыть окно браузера и попросить войти в аккаунт. Обычный пароль аккаунта в консоли GitHub больше не принимает; используйте вход через браузер или Personal Access Token.

Если `pull --rebase` сообщает о конфликте, не используйте `push --force`, `reset --hard` или случайное удаление файлов. Остановитесь и сохраните полный текст ошибки для разбора.

## 8. Создать тег

После успешного push:

```powershell
git tag -a v3.0.7-sb.4 -m "keen-pbr-sb v3.0.7-sb.4"
git push origin v3.0.7-sb.4
```

Если Git отвечает, что тег уже существует, сначала проверьте страницу Tags на GitHub. Не перезаписывайте опубликованный тег молча.

## 9. Создать GitHub Release

1. Откройте `https://github.com/blindtechnique/keen-pbr-sb`.
2. Справа нажмите **Releases**, затем **Draft a new release**.
3. В поле тега выберите существующий `v3.0.7-sb.4`.
4. В заголовке напишите `keen-pbr-sb v3.0.7-sb.4`.
5. В описание вставьте содержимое подготовленного файла `RELEASE_NOTES.md`. Не оставляйте описание пустым: именно этот текст пользователь увидит в веб-интерфейсе перед обновлением. Подробная история всех версий хранится в корневом `CHANGELOG.md` и будет доступна по отдельной ссылке.
6. Перетащите в область вложений только:

   ```text
   keen-pbr_3.0.7-4_keenetic_aarch64-3.10.ipk
   SHA256SUMS
   ```

7. Не отмечайте выпуск как pre-release, если хотите, чтобы однострочный установщик и OTA нашли его через `releases/latest`.
8. Нажмите **Publish release**.

## 10. Проверить публикацию

На странице Release убедитесь, что:

- он помечен как `Latest`;
- имена IPK и `SHA256SUMS` не изменились;
- `SHA256SUMS` содержит строку для этого IPK;
- корень репозитория показывает русский README;
- в корне доступен `CHANGELOG.md`, а описание Release содержит понятный список изменений;
- в репозитории отсутствуют ключи, пароли, `build`, `.cache` и `node_modules`.

После этого на чистом Entware проверьте установку:

```sh
sh -c "$(curl -fsSL https://raw.githubusercontent.com/blindtechnique/keen-pbr-sb/main/install.sh)"
```

## 11. SSH после полного сброса Entware

Полный сброс Entware удаляет Dropbear и файл ключей. Это нормально и не относится к keen-pbr-sb. Перед удалённой диагностикой заново добавьте тестовый публичный ключ в:

```text
/opt/etc/dropbear/authorized_keys
```

Пример на роутере:

```sh
mkdir -p /opt/etc/dropbear
printf '%s\n' 'ВАШ_ПУБЛИЧНЫЙ_SSH_КЛЮЧ' >> /opt/etc/dropbear/authorized_keys
chmod 600 /opt/etc/dropbear/authorized_keys
/opt/etc/init.d/S51dropbear restart
```

Используйте `>>`, если в файле уже есть другие нужные ключи. Приватный ключ никогда не копируйте на роутер, в архив или GitHub.

## 12. Как публиковать следующие версии

Для следующего выпуска повторите шаги 3–10 с новым номером release в `version.mk`, новым тегом и новым IPK. Обычная последовательность после внесения изменений:

```powershell
git pull --rebase origin main
git add --all
git commit -m "release: keen-pbr-sb НОВАЯ_ВЕРСИЯ"
git push origin main
git tag -a НОВЫЙ_ТЕГ -m "keen-pbr-sb НОВАЯ_ВЕРСИЯ"
git push origin НОВЫЙ_ТЕГ
```

Затем вручную создайте Release и приложите новый IPK с новым `SHA256SUMS`.

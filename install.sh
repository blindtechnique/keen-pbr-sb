#!/bin/sh

set -eu

PROJECT_REPOSITORY="${MYKEENPBR_REPOSITORY:-blindtechnique/keen-pbr-sb}"
GITHUB_API="https://api.github.com/repos"
SING_BOX_TESTED_VERSION="1.13.14"
TMP_DIR="${TMPDIR:-/tmp}/mykeenpbr-install.$$"
TRANSPORT_CONFIG="/opt/etc/keen-pbr/transports.json"
UPDATE_ONLY=0

case "${1:-}" in
    --update) UPDATE_ONLY=1 ;;
    "") ;;
    *) printf '%s\n' "ОШИБКА: неизвестный параметр: $1" >&2; exit 2 ;;
esac

cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

say() {
    printf '%s\n' "$*"
}

die() {
    say "ОШИБКА: $*" >&2
    exit 1
}

ask() {
    prompt="$1"
    default="$2"
    printf '%s ' "$prompt" >/dev/tty
    answer=""
    IFS= read -r answer </dev/tty || true
    [ -n "$answer" ] || answer="$default"
    printf '%s' "$answer"
}

ask_secret() {
    prompt="$1"
    printf '%s ' "$prompt" >/dev/tty
    stty -echo </dev/tty 2>/dev/null || true
    answer=""
    IFS= read -r answer </dev/tty || true
    stty echo </dev/tty 2>/dev/null || true
    printf '\n' >/dev/tty
    printf '%s' "$answer"
}

fetch() {
    url="$1"
    output="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fL --connect-timeout 15 --retry 3 -o "$output" "$url"
    elif [ -x /opt/bin/curl ]; then
        /opt/bin/curl -fL --connect-timeout 15 --retry 3 -o "$output" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -O "$output" "$url"
    else
        die "требуется curl или wget"
    fi
}

github_asset_urls() {
    grep '"browser_download_url"' "$1" | cut -d '"' -f 4
}

detect_target() {
    [ -x /opt/bin/opkg ] || die "Entware не подключён в /opt"
    architecture=$(/opt/bin/opkg print-architecture | awk '
        $2 != "all" && $2 !~ /_kn$/ && $3 >= priority { arch=$2; priority=$3 }
        END { print arch }
    ')
    case "$architecture" in
        aarch64-*) KEEN_ARCH="aarch64" ;;
        armv7-*) KEEN_ARCH="armv7" ;;
        mipsel-*) KEEN_ARCH="mipsel" ;;
        mips-*) KEEN_ARCH="mips" ;;
        x64-*) KEEN_ARCH="x64" ;;
        *) die "неподдерживаемая архитектура Entware: ${architecture:-неизвестно}" ;;
    esac
    KEEN_ABI=${architecture#*-}
}

download_package() {
    release_json="$TMP_DIR/release.json"
    fetch "$GITHUB_API/$PROJECT_REPOSITORY/releases/latest" "$release_json"
    pattern="/keen-pbr_[^/]*_keenetic_${KEEN_ARCH}-${KEEN_ABI}\\.ipk$"
    package_url=$(github_asset_urls "$release_json" | grep -E "$pattern" | head -n 1 || true)
    [ -n "$package_url" ] || die "в Release нет полного пакета Keenetic для ${KEEN_ARCH}-${KEEN_ABI}"
    PACKAGE_FILE="$TMP_DIR/$(basename "$package_url")"
    fetch "$package_url" "$PACKAGE_FILE"

    sums_url=$(github_asset_urls "$release_json" | grep '/SHA256SUMS$' | head -n 1 || true)
    if [ -n "$sums_url" ]; then
        fetch "$sums_url" "$TMP_DIR/SHA256SUMS"
        expected=$(awk -v name="$(basename "$PACKAGE_FILE")" '$2 == name || $2 == "*" name { print $1; exit }' "$TMP_DIR/SHA256SUMS")
        [ -n "$expected" ] || die "пакет отсутствует в SHA256SUMS"
        actual=$(sha256sum "$PACKAGE_FILE" | awk '{print $1}')
        [ "$actual" = "$expected" ] || die "контрольная сумма пакета не совпадает"
    else
        say "ПРЕДУПРЕЖДЕНИЕ: в Release нет SHA256SUMS; загрузка защищена TLS, но файл не проверен по отдельной контрольной сумме."
    fi
}

find_existing_sing_box() {
    for candidate in \
        /opt/bin/sing-box \
        /opt/sbin/sing-box \
        /opt/usr/bin/sing-box \
        /opt/etc/awg-manager/singbox/sing-box
    do
        if [ -x "$candidate" ] && "$candidate" version >/dev/null 2>&1; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    return 1
}

make_entware_sing_box_wrapper() {
    binary=$1
    real_binary="${binary}.real"
    loader=""
    for candidate in /opt/lib/ld-*.so*; do
        [ -e "$candidate" ] || continue
        loader=$candidate
        break
    done
    [ -n "$loader" ] || return 1

    mv "$binary" "$real_binary"
    cat > "$binary" <<EOF
#!/bin/sh
exec "$loader" --library-path /opt/lib:/opt/usr/lib "$real_binary" "\$@"
EOF
    chmod 0755 "$binary"
    if "$binary" version >/dev/null 2>&1; then
        return 0
    fi

    rm -f "$binary"
    mv "$real_binary" "$binary"
    return 1
}

sing_box_version() {
    "$1" version 2>/dev/null | awk 'NR == 1 { print $3; exit }'
}

latest_sing_box_version() {
    release_json="$TMP_DIR/sing-box-latest.json"
    fetch "$GITHUB_API/SagerNet/sing-box/releases/latest" "$release_json"
    grep '"tag_name"' "$release_json" | head -n 1 | cut -d '"' -f 4 | sed 's/^v//'
}

install_sing_box() {
    requested_version=$1
    case "$KEEN_ARCH" in
        aarch64) sing_arch="arm64" ;;
        armv7) sing_arch="armv7" ;;
        mipsel) sing_arch="mipsle" ;;
        mips) sing_arch="mips" ;;
        x64) sing_arch="amd64" ;;
        *) die "для архитектуры $KEEN_ARCH не задан официальный архив sing-box" ;;
    esac

    release_json="$TMP_DIR/sing-box-release-${requested_version}.json"
    fetch "$GITHUB_API/SagerNet/sing-box/releases/tags/v${requested_version}" "$release_json"
    archive_url=$(github_asset_urls "$release_json" | grep -E "/sing-box-${requested_version}-linux-${sing_arch}\\.tar\\.gz$" | head -n 1 || true)
    [ -n "$archive_url" ] || die "в официальном выпуске sing-box ${requested_version} нет архива linux-$sing_arch"
    archive="$TMP_DIR/$(basename "$archive_url")"
    fetch "$archive_url" "$archive"

    checksums_url=$(github_asset_urls "$release_json" | grep -E '/sing-box-[^/]+-checksums\\.txt$' | head -n 1 || true)
    if [ -n "$checksums_url" ]; then
        fetch "$checksums_url" "$TMP_DIR/sing-box-checksums.txt"
        expected=$(awk -v name="$(basename "$archive")" '$2 == name || $2 == "*" name { print $1; exit }' "$TMP_DIR/sing-box-checksums.txt")
        [ -n "$expected" ] || die "архив sing-box отсутствует в файле контрольных сумм"
        actual=$(sha256sum "$archive" | awk '{print $1}')
        [ "$actual" = "$expected" ] || die "контрольная сумма sing-box не совпадает"
    fi

    mkdir -p "$TMP_DIR/sing-box" /opt/bin /opt/etc/keen-pbr
    tar -xzf "$archive" -C "$TMP_DIR/sing-box"
    binary=$(find "$TMP_DIR/sing-box" -type f -name sing-box | head -n 1)
    [ -n "$binary" ] || die "исполняемый файл sing-box не найден в архиве"
    cp "$binary" /opt/bin/sing-box
    chmod 0755 /opt/bin/sing-box
    if ! /opt/bin/sing-box version >/dev/null 2>&1; then
        if ! make_entware_sing_box_wrapper /opt/bin/sing-box; then
            rm -f /opt/bin/sing-box /opt/bin/sing-box.real
            die "официальный sing-box не запускается с ABI установленного Entware"
        fi
    fi
    printf '%s\n' /opt/bin/sing-box > /opt/etc/keen-pbr/sing-box-managed.path
    SING_BOX_PATH=/opt/bin/sing-box
}

choose_sing_box() {
    existing=$(find_existing_sing_box || true)
    latest=$(latest_sing_box_version || true)
    [ -n "$latest" ] || latest="$SING_BOX_TESTED_VERSION"
    if [ -n "$existing" ]; then
        current=$(sing_box_version "$existing")
        say "Найден sing-box: $existing (версия ${current:-не определена})"
        say "  1) Использовать найденный файл (рекомендуется, если он уже проверен)"
        say "  2) Установить протестированную версию $SING_BOX_TESTED_VERSION в /opt/bin"
        say "  3) Установить последнюю версию $latest"
        say "  4) Указать другой существующий путь"
        say "  5) Продолжить без sing-box (только нативные интерфейсы)"
        if [ "$latest" != "$SING_BOX_TESTED_VERSION" ]; then
            say "ПРЕДУПРЕЖДЕНИЕ: версия $latest новее протестированной $SING_BOX_TESTED_VERSION; совместимость не проверялась."
        fi
        choice=$(ask "Выберите [1-5] (по умолчанию 1):" "1")
    else
        say "sing-box не найден в стандартных каталогах."
        say "  1) Установить протестированную версию $SING_BOX_TESTED_VERSION в /opt/bin (рекомендуется)"
        say "  2) Установить последнюю версию $latest"
        say "  3) Указать другой существующий путь"
        say "  4) Продолжить без sing-box (только нативные интерфейсы)"
        if [ "$latest" != "$SING_BOX_TESTED_VERSION" ]; then
            say "ПРЕДУПРЕЖДЕНИЕ: версия $latest новее протестированной $SING_BOX_TESTED_VERSION; совместимость не проверялась."
        fi
        choice=$(ask "Выберите [1-4] (по умолчанию 1):" "1")
        case "$choice" in 1) choice=2 ;; 2) choice=3 ;; 3) choice=4 ;; 4) choice=5 ;; *) die "неверный выбор" ;; esac
    fi

    case "$choice" in
        1) SING_BOX_PATH="$existing" ;;
        2) install_sing_box "$SING_BOX_TESTED_VERSION" ;;
        3)
            if [ "$latest" != "$SING_BOX_TESTED_VERSION" ]; then
                confirm=$(ask "Установить непроверенную версию $latest? [y/N]:" "N")
                case "$confirm" in y|Y|yes|YES|д|Д|да|ДА) ;; *) die "установка новой версии отменена" ;; esac
            fi
            install_sing_box "$latest"
            ;;
        4)
            SING_BOX_PATH=$(ask "Абсолютный путь к sing-box:" "")
            [ -x "$SING_BOX_PATH" ] || die "файл не является исполняемым: $SING_BOX_PATH"
            "$SING_BOX_PATH" version >/dev/null || die "выбранный sing-box не запускается"
            ;;
        5) SING_BOX_PATH="" ;;
        *) die "неверный выбор" ;;
    esac
}

set_sing_box_path() {
    [ -n "$SING_BOX_PATH" ] || return 0
    [ -f "$TRANSPORT_CONFIG" ] || die "конфигурация транспортов не установлена"
    escaped=$(printf '%s' "$SING_BOX_PATH" | sed 's/[\\&|]/\\&/g')
    sed -i "s|\"sing_box_binary\"[[:space:]]*:[[:space:]]*\"[^\"]*\"|\"sing_box_binary\": \"$escaped\"|" "$TRANSPORT_CONFIG"
    chmod 0600 "$TRANSPORT_CONFIG"
    /opt/etc/init.d/S79transport-manager restart
}

configure_web_auth() {
    auth_file=/opt/etc/keen-pbr/auth.json
    if [ -f "$auth_file" ]; then
        keep=$(ask "Сохранить существующие настройки авторизации веб-интерфейса? [Y/n]:" "Y")
        case "$keep" in
            n|N|no|NO) ;;
            *) return 0 ;;
        esac
    fi

    enable=$(ask "Включить защиту веб-интерфейса паролем? [Y/n]:" "Y")
    case "$enable" in
        n|N|no|NO)
            printf '%s\n' '{"enabled":false}' > "$auth_file"
            chmod 0600 "$auth_file"
            /opt/etc/init.d/S80keen-pbr restart
            return 0
            ;;
    esac

    say "По возможности используйте отдельный пароль. Можно ввести реквизиты root Entware или администратора Keenetic, но keen-pbr-sb хранит и проверяет собственную локальную копию."
    username=$(ask "Логин веб-интерфейса (по умолчанию admin):" "admin")
    password=$(ask_secret "Пароль веб-интерфейса:")
    [ -n "$password" ] || die "пароль веб-интерфейса не может быть пустым"
    escaped_username=$(printf '%s' "$username" | sed 's/[\\"]/\\&/g')
    escaped_password=$(printf '%s' "$password" | sed 's/[\\"]/\\&/g')
    umask 077
    printf '{"enabled":true,"username":"%s","password":"%s","session_ttl_seconds":604800}\n' \
        "$escaped_username" "$escaped_password" > "$auth_file"
    chmod 0600 "$auth_file"
    /opt/etc/init.d/S80keen-pbr restart
}

configure_dns() {
    answer=$(ask "Включить Keenetic DNS Override и настроить dnsmasq Entware? [Y/n]:" "Y")
    case "$answer" in
        n|N|no|NO) return 0 ;;
    esac

    template=/opt/usr/lib/keen-pbr/dnsmasq.conf.template
    config=/opt/etc/dnsmasq.conf
    [ -f "$template" ] || die "шаблон dnsmasq отсутствует"
    /opt/sbin/dnsmasq --test --conf-file="$template" >/dev/null 2>&1 || die "сгенерированная конфигурация dnsmasq некорректна"
    backup="$config.backup-mykeenpbr-$(date +%Y%m%d%H%M%S)"
    [ ! -f "$config" ] || cp -p "$config" "$backup"

    cp "$template" "$config"
    chmod 0600 "$config"
    if ! ndmc -c "opkg dns-override" >/dev/null ||
       ! ndmc -c "system configuration save" >/dev/null; then
        [ ! -f "$backup" ] || cp -p "$backup" "$config"
        die "не удалось включить opkg dns-override"
    fi
    if ! /opt/etc/init.d/S56dnsmasq restart >/dev/null 2>&1; then
        [ ! -f "$backup" ] || cp -p "$backup" "$config"
        ndmc -c "no opkg dns-override" >/dev/null 2>&1 || true
        ndmc -c "system configuration save" >/dev/null 2>&1 || true
        die "dnsmasq не запустился; DNS Override отменён"
    fi
    if ! nslookup google.com 127.0.0.1 >/dev/null 2>&1; then
        say "ПРЕДУПРЕЖДЕНИЕ: dnsmasq запущен, но быстрая проверка внешнего DNS не прошла."
        say "Установка продолжится; проверьте состояние DNS и диагностику в веб-интерфейсе."
    fi
}

configure_nfqws2() {
    if /opt/bin/opkg status nfqws2-keenetic 2>/dev/null | grep -q '^Status:.* installed'; then
        answer=$(ask "nfqws2 уже установлен. Обновить его из официального репозитория? [y/N]:" "N")
    else
        answer=$(ask "Установить nfqws2 из официального репозитория nfqws/nfqws2-keenetic? [y/N]:" "N")
    fi
    case "$answer" in y|Y|yes|YES|д|Д|да|ДА) ;; *) return 0 ;; esac

    say "Подготавливаю HTTPS и официальный репозиторий nfqws2..."
    # Старый wget из Entware понимает только HTTP/FTP. Сначала обновляем
    # обычные feeds и заменяем его на SSL-вариант, и только после этого
    # добавляем HTTPS-feed nfqws2. Удаление feed также чинит повторный запуск
    # после ранее прерванной установки.
    mkdir -p /opt/etc/opkg
    rm -f /opt/etc/opkg/nfqws2-keenetic.conf
    /opt/bin/opkg update || die "не удалось обновить список пакетов Entware"
    /opt/bin/opkg install ca-certificates wget-ssl || die "не удалось установить HTTPS-зависимости nfqws2"
    /opt/bin/opkg remove wget-nossl >/dev/null 2>&1 || true
    printf '%s\n' 'src/gz nfqws2-keenetic https://nfqws.github.io/nfqws2-keenetic/all' > /opt/etc/opkg/nfqws2-keenetic.conf
    /opt/bin/opkg update || die "не удалось загрузить официальный репозиторий nfqws2"
    say "Устанавливаю пакет nfqws2..."
    if /opt/bin/opkg status nfqws2-keenetic 2>/dev/null | grep -q '^Status:.* installed'; then
        /opt/bin/opkg upgrade nfqws2-keenetic || die "не удалось обновить nfqws2"
    else
        /opt/bin/opkg install nfqws2-keenetic || die "не удалось установить nfqws2"
    fi
    say "nfqws2 установлен. Управление доступно в разделе «nfqws2» веб-интерфейса keen-pbr-sb."
}

repair_interrupted_nfqws_bootstrap() {
    feed=/opt/etc/opkg/nfqws2-keenetic.conf
    [ -f "$feed" ] || return 0
    if /opt/bin/opkg status wget-ssl 2>/dev/null | grep -q '^Status:.* installed'; then
        return 0
    fi
    say "Обнаружена незавершённая настройка nfqws2. Сначала восстанавливаю поддержку HTTPS..."
    saved_feed="$TMP_DIR/nfqws2-keenetic.conf"
    mv "$feed" "$saved_feed"
    /opt/bin/opkg update || die "не удалось обновить пакеты Entware при восстановлении HTTPS"
    /opt/bin/opkg install ca-certificates wget-ssl || die "не удалось установить wget с поддержкой HTTPS"
    /opt/bin/opkg remove wget-nossl >/dev/null 2>&1 || true
    mv "$saved_feed" "$feed"
}

[ "$(id -u)" = "0" ] || die "запустите установщик от пользователя root"
mkdir -p "$TMP_DIR"
detect_target
say "Установка keen-pbr-sb для ${KEEN_ARCH}-${KEEN_ABI} из $PROJECT_REPOSITORY"
download_package
if [ "$UPDATE_ONLY" = "1" ]; then
    say "Устанавливаю обновление keen-pbr-sb без изменения пользовательских настроек..."
    KEEN_PBR_REPLACE_DNSMASQ_DEFAULTS=N /opt/bin/opkg install "$PACKAGE_FILE"
    say "Обновление keen-pbr-sb установлено. Веб-интерфейс перезапускается."
    exit 0
fi
choose_sing_box
repair_interrupted_nfqws_bootstrap
/opt/bin/opkg update
KEEN_PBR_REPLACE_DNSMASQ_DEFAULTS=N /opt/bin/opkg install "$PACKAGE_FILE"
set_sing_box_path
configure_web_auth
configure_dns
configure_nfqws2

say ""
say "Установка завершена."
say "Веб-интерфейс: http://my.keenetic.net:12121/"
say "Каталог конфигурации и резервных копий: /opt/etc/keen-pbr"

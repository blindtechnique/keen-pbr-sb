#!/bin/sh

set -eu

PROJECT_REPOSITORY="${MYKEENPBR_REPOSITORY:-blindtechnique/keen-pbr-sb}"
GITHUB_API="https://api.github.com/repos"
TMP_DIR="${TMPDIR:-/tmp}/mykeenpbr-install.$$"
TRANSPORT_CONFIG="/opt/etc/keen-pbr/transports.json"

cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

say() {
    printf '%s\n' "$*"
}

die() {
    say "ERROR: $*" >&2
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
        die "curl or wget is required"
    fi
}

github_asset_urls() {
    grep '"browser_download_url"' "$1" | cut -d '"' -f 4
}

detect_target() {
    [ -x /opt/bin/opkg ] || die "Entware is not mounted at /opt"
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
        *) die "unsupported Entware architecture: ${architecture:-unknown}" ;;
    esac
    KEEN_ABI=${architecture#*-}
}

download_package() {
    release_json="$TMP_DIR/release.json"
    fetch "$GITHUB_API/$PROJECT_REPOSITORY/releases/latest" "$release_json"
    pattern="/keen-pbr_[^/]*_keenetic_${KEEN_ARCH}-${KEEN_ABI}\\.ipk$"
    package_url=$(github_asset_urls "$release_json" | grep -E "$pattern" | head -n 1 || true)
    [ -n "$package_url" ] || die "release has no full Keenetic package for ${KEEN_ARCH}-${KEEN_ABI}"
    PACKAGE_FILE="$TMP_DIR/$(basename "$package_url")"
    fetch "$package_url" "$PACKAGE_FILE"

    sums_url=$(github_asset_urls "$release_json" | grep '/SHA256SUMS$' | head -n 1 || true)
    if [ -n "$sums_url" ]; then
        fetch "$sums_url" "$TMP_DIR/SHA256SUMS"
        expected=$(awk -v name="$(basename "$PACKAGE_FILE")" '$2 == name || $2 == "*" name { print $1; exit }' "$TMP_DIR/SHA256SUMS")
        [ -n "$expected" ] || die "package is missing from SHA256SUMS"
        actual=$(sha256sum "$PACKAGE_FILE" | awk '{print $1}')
        [ "$actual" = "$expected" ] || die "package checksum mismatch"
    else
        say "WARNING: this release has no SHA256SUMS; TLS download was used without an asset checksum."
    fi
}

find_existing_sing_box() {
    for candidate in \
        /opt/bin/sing-box \
        /opt/sbin/sing-box \
        /opt/usr/bin/sing-box \
        /opt/etc/awg-manager/singbox/sing-box
    do
        if [ -x "$candidate" ]; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    return 1
}

install_sing_box() {
    case "$KEEN_ARCH" in
        aarch64) sing_arch="arm64" ;;
        armv7) sing_arch="armv7" ;;
        mipsel) sing_arch="mipsle" ;;
        mips) sing_arch="mips" ;;
        x64) sing_arch="amd64" ;;
        *) die "sing-box downloads are not mapped for $KEEN_ARCH" ;;
    esac

    release_json="$TMP_DIR/sing-box-release.json"
    fetch "$GITHUB_API/SagerNet/sing-box/releases/latest" "$release_json"
    archive_url=$(github_asset_urls "$release_json" | grep -E "/sing-box-[^/]+-linux-${sing_arch}\\.tar\\.gz$" | head -n 1 || true)
    [ -n "$archive_url" ] || die "official sing-box release has no linux-$sing_arch archive"
    archive="$TMP_DIR/$(basename "$archive_url")"
    fetch "$archive_url" "$archive"

    checksums_url=$(github_asset_urls "$release_json" | grep -E '/sing-box-[^/]+-checksums\\.txt$' | head -n 1 || true)
    if [ -n "$checksums_url" ]; then
        fetch "$checksums_url" "$TMP_DIR/sing-box-checksums.txt"
        expected=$(awk -v name="$(basename "$archive")" '$2 == name || $2 == "*" name { print $1; exit }' "$TMP_DIR/sing-box-checksums.txt")
        [ -n "$expected" ] || die "sing-box archive is missing from its checksum file"
        actual=$(sha256sum "$archive" | awk '{print $1}')
        [ "$actual" = "$expected" ] || die "sing-box checksum mismatch"
    fi

    mkdir -p "$TMP_DIR/sing-box" /opt/bin /opt/etc/keen-pbr
    tar -xzf "$archive" -C "$TMP_DIR/sing-box"
    binary=$(find "$TMP_DIR/sing-box" -type f -name sing-box | head -n 1)
    [ -n "$binary" ] || die "sing-box binary was not found in the archive"
    cp "$binary" /opt/bin/sing-box
    chmod 0755 /opt/bin/sing-box
    /opt/bin/sing-box version >/dev/null
    printf '%s\n' /opt/bin/sing-box > /opt/etc/keen-pbr/sing-box-managed.path
    SING_BOX_PATH=/opt/bin/sing-box
}

choose_sing_box() {
    existing=$(find_existing_sing_box || true)
    if [ -n "$existing" ]; then
        say "Found sing-box: $existing"
        say "  1) Use the detected binary (recommended)"
        say "  2) Install/update an independent official binary in /opt/bin"
        say "  3) Use another existing path"
        say "  4) Continue without sing-box (native interfaces only)"
        choice=$(ask "Select [1-4] (default 1):" "1")
    else
        say "sing-box was not found in the standard locations."
        say "  1) Install the latest official release in /opt/bin (recommended)"
        say "  2) Use an existing binary at another path"
        say "  3) Continue without sing-box (native interfaces only)"
        choice=$(ask "Select [1-3] (default 1):" "1")
        case "$choice" in
            1) choice=2 ;;
            2) choice=3 ;;
            3) choice=4 ;;
            *) die "invalid selection" ;;
        esac
    fi

    case "$choice" in
        1) SING_BOX_PATH="$existing" ;;
        2) install_sing_box ;;
        3)
            SING_BOX_PATH=$(ask "Absolute path to sing-box:" "")
            [ -x "$SING_BOX_PATH" ] || die "not executable: $SING_BOX_PATH"
            "$SING_BOX_PATH" version >/dev/null || die "the selected binary does not run"
            ;;
        4) SING_BOX_PATH="" ;;
        *) die "invalid selection" ;;
    esac
}

set_sing_box_path() {
    [ -n "$SING_BOX_PATH" ] || return 0
    [ -f "$TRANSPORT_CONFIG" ] || die "transport config was not installed"
    escaped=$(printf '%s' "$SING_BOX_PATH" | sed 's/[\\&|]/\\&/g')
    sed -i "s|\"sing_box_binary\"[[:space:]]*:[[:space:]]*\"[^\"]*\"|\"sing_box_binary\": \"$escaped\"|" "$TRANSPORT_CONFIG"
    chmod 0600 "$TRANSPORT_CONFIG"
    /opt/etc/init.d/S79transport-manager restart
}

configure_dns() {
    answer=$(ask "Enable Keenetic DNS Override and configure Entware dnsmasq? [Y/n]:" "Y")
    case "$answer" in
        n|N|no|NO) return 0 ;;
    esac

    template=/opt/usr/lib/keen-pbr/dnsmasq.conf.template
    config=/opt/etc/dnsmasq.conf
    [ -f "$template" ] || die "dnsmasq template is missing"
    /opt/sbin/dnsmasq --test --conf-file="$template" >/dev/null 2>&1 || die "generated dnsmasq configuration is invalid"
    backup="$config.backup-mykeenpbr-$(date +%Y%m%d%H%M%S)"
    [ ! -f "$config" ] || cp -p "$config" "$backup"

    cp "$template" "$config"
    chmod 0600 "$config"
    if ! ndmc -c "opkg dns-override" >/dev/null ||
       ! ndmc -c "system configuration save" >/dev/null; then
        [ ! -f "$backup" ] || cp -p "$backup" "$config"
        die "failed to enable opkg dns-override"
    fi
    if ! /opt/etc/init.d/S56dnsmasq restart >/dev/null 2>&1; then
        [ ! -f "$backup" ] || cp -p "$backup" "$config"
        ndmc -c "no opkg dns-override" >/dev/null 2>&1 || true
        ndmc -c "system configuration save" >/dev/null 2>&1 || true
        die "dnsmasq did not start; DNS Override was rolled back"
    fi
    nslookup google.com 127.0.0.1 >/dev/null 2>&1 || die "dnsmasq started but its upstream resolution failed"
}

[ "$(id -u)" = "0" ] || die "run this installer as root"
mkdir -p "$TMP_DIR"
detect_target
say "Installing MyKeenPBR for ${KEEN_ARCH}-${KEEN_ABI} from $PROJECT_REPOSITORY"
download_package
choose_sing_box
/opt/bin/opkg update
KEEN_PBR_REPLACE_DNSMASQ_DEFAULTS=N /opt/bin/opkg install "$PACKAGE_FILE"
set_sing_box_path
configure_dns

say ""
say "Installation completed."
say "Web UI: http://my.keenetic.net:12121/"
say "Backup and configuration directory: /opt/etc/keen-pbr"

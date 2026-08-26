#!/bin/sh
# build-keenetic-package.sh — Compile keen-pbr inside an Entware build tree.
#
# Usage: scripts/build-keenetic-package.sh <workspace-dir> <entware-dir>
#
# This script is intended to run INSIDE the entware-builder Docker container
# (ghcr.io/maksimkurb/entware-builder:<config>), with the keen-pbr source tree
# mounted at <workspace-dir>.
#
# <workspace-dir>  Path to the keen-pbr source tree (contains version.mk, packages/, …)
# <entware-dir>    Path to the Entware build tree (e.g. /home/me/Entware)

set -eu

WORKSPACE="${1:?Usage: $0 <workspace-dir> <entware-dir>}"
ENTWARE_DIR="${2:?}"
FRONTEND_DIST="${KEEN_PBR_FRONTEND_DIST:-$WORKSPACE/frontend/dist}"
KEEN_PBR_RELEASE="$(bash "$WORKSPACE/build_scripts/resolve-version.sh" release "$WORKSPACE")"
KEEN_PBR_COMMIT="$(bash "$WORKSPACE/build_scripts/resolve-version.sh" commit "$WORKSPACE")"
: "${KEEN_PBR_TRANSPORT_MANAGER_BIN:?KEEN_PBR_TRANSPORT_MANAGER_BIN is required}"
KEEN_PBR_JOBS="${KEEN_PBR_JOBS:-2}"

case "$KEEN_PBR_JOBS" in
    ''|*[!0-9]*|0)
        echo "KEEN_PBR_JOBS must be a positive integer" >&2
        exit 1
        ;;
esac

KEEN_PBR_RELEASE_OVERRIDE="$KEEN_PBR_RELEASE" \
    sh "$WORKSPACE/build_scripts/ensure-frontend-dist.sh" \
        "$WORKSPACE" "$FRONTEND_DIST"

cd "$ENTWARE_DIR"
# Reusable builder images may already contain our local feed from a previous
# build. Keep a single entry so feeds update does not abort on duplicates.
sed -i '/^src-link keenPbr /d' feeds.conf
printf '\nsrc-link keenPbr %s/packages/keenetic\n' "$WORKSPACE" >> feeds.conf
./scripts/feeds update keenPbr
# conntrack is a runtime dependency used for targeted mark cleanup. Reusable
# Entware builders do not consistently keep every feed package installed in
# package/feeds, and OpenWrt silently drops an unresolved dependency from the
# resulting control file.
./scripts/feeds install conntrack
./scripts/feeds install -p keenPbr keen-pbr
FEED_PKG_DIR="package/feeds/keenPbr/keen-pbr"
if [ ! -d "$FEED_PKG_DIR" ]; then
    echo "[build-keenetic-package] Feed installation did not create $FEED_PKG_DIR" >&2
    exit 1
fi
cp "$WORKSPACE/version.mk" "$FEED_PKG_DIR/version.mk"
cat "$WORKSPACE/packages/keenetic/packages.config" >> .config
make defconfig
if ! grep -Eq '^CONFIG_PACKAGE_keen-pbr=(m|y)$' .config; then
    echo "[build-keenetic-package] Required package is not selected after defconfig: keen-pbr" >&2
    exit 1
fi
if ! grep -Eq '^CONFIG_PACKAGE_conntrack=(m|y)$' .config; then
    echo "[build-keenetic-package] Required runtime dependency is not selected after defconfig: conntrack" >&2
    exit 1
fi
make package/keen-pbr/compile V=s "-j$KEEN_PBR_JOBS" \
    KEEN_PBR_SRC="$WORKSPACE" \
    KEEN_PBR_FRONTEND_DIST="$FRONTEND_DIST" \
    KEEN_PBR_TRANSPORT_MANAGER_BIN="$KEEN_PBR_TRANSPORT_MANAGER_BIN" \
    KEEN_PBR_RELEASE="$KEEN_PBR_RELEASE" \
    KEEN_PBR_COMMIT="$KEEN_PBR_COMMIT"

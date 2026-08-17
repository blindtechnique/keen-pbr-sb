#!/bin/sh

set -eu

WORKSPACE="${1:?Usage: $0 <workspace-dir> [output-dir]}"
OUTPUT_DIR="${2:-$WORKSPACE/frontend/dist}"
SOURCE_ID_SCRIPT="$WORKSPACE/build_scripts/frontend-source-id.sh"
MARKER_NAME=".keen-pbr-source-id"
BUN_BIN=

ensure_bun() {
    if command -v bun >/dev/null 2>&1; then
        BUN_BIN="$(command -v bun)"
        return
    fi

    if [ -n "${BUN_INSTALL:-}" ] && [ -x "$BUN_INSTALL/bin/bun" ]; then
        BUN_BIN="$BUN_INSTALL/bin/bun"
        return
    fi

    if [ -n "${HOME:-}" ] && [ -x "$HOME/.bun/bin/bun" ]; then
        BUN_BIN="$HOME/.bun/bin/bun"
        return
    fi

    echo "ERROR: Bun is required to build the frontend; install it before packaging." >&2
    echo "       A detached verified bundle may use KEEN_PBR_FRONTEND_DIST_MODE=prebuilt." >&2
    exit 1
}

ensure_bun

if [ ! -f "$SOURCE_ID_SCRIPT" ]; then
    echo "ERROR: frontend source fingerprint helper is missing: $SOURCE_ID_SCRIPT" >&2
    exit 1
fi

SOURCE_ID_BEFORE="$(sh "$SOURCE_ID_SCRIPT" "$WORKSPACE")"

TMP_ROOT="${TMPDIR:-/tmp}/keen-pbr-bun"
TMP_BUILD_DIR="$(mktemp -d "${TMP_ROOT}.dist.XXXXXX")"
trap 'rm -rf "$TMP_BUILD_DIR"' EXIT HUP INT TERM

mkdir -p "${TMP_ROOT}"

cd "$WORKSPACE/frontend"
TMPDIR="${TMP_ROOT}" TEMP="${TMP_ROOT}" TMP="${TMP_ROOT}" BUN_INSTALL_CACHE_DIR="${TMP_ROOT}/cache" \
    "$BUN_BIN" install --frozen-lockfile
TMPDIR="${TMP_ROOT}" TEMP="${TMP_ROOT}" TMP="${TMP_ROOT}" BUN_INSTALL_CACHE_DIR="${TMP_ROOT}/cache" \
    KEEN_PBR_FRONTEND_OUT_DIR="$TMP_BUILD_DIR" "$BUN_BIN" run build

if [ ! -s "$TMP_BUILD_DIR/index.html" ]; then
    echo "ERROR: frontend build did not produce index.html." >&2
    exit 1
fi

SOURCE_ID_AFTER="$(sh "$SOURCE_ID_SCRIPT" "$WORKSPACE")"
if [ "$SOURCE_ID_AFTER" != "$SOURCE_ID_BEFORE" ]; then
    echo "ERROR: frontend inputs changed while the bundle was being built." >&2
    exit 1
fi
printf '%s\n' "$SOURCE_ID_AFTER" > "$TMP_BUILD_DIR/$MARKER_NAME"

rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"
cp -a "$TMP_BUILD_DIR"/. "$OUTPUT_DIR"/

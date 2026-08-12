#!/bin/sh

set -eu

WORKSPACE="${1:?Usage: $0 <workspace-dir> [dist-dir]}"
DIST_DIR="${2:-$WORKSPACE/frontend/dist}"
MODE="${KEEN_PBR_FRONTEND_DIST_MODE:-source}"
MARKER="$DIST_DIR/.keen-pbr-source-id"

case "$MODE" in
    source)
        EXPECTED_ID="$(
            sh "$WORKSPACE/build_scripts/frontend-source-id.sh" "$WORKSPACE"
        )"
        if [ -s "$DIST_DIR/index.html" ] && [ -f "$MARKER" ]; then
            ACTUAL_ID="$(cat "$MARKER")"
            if [ "$ACTUAL_ID" = "$EXPECTED_ID" ]; then
                exit 0
            fi
        fi
        echo "[ensure-frontend-dist] Frontend bundle is missing or stale; rebuilding it." >&2
        ;;
    prebuilt)
        if [ ! -s "$DIST_DIR/index.html" ]; then
            echo "ERROR: trusted prebuilt frontend is missing index.html: $DIST_DIR" >&2
            exit 1
        fi
        exit 0
        ;;
    *)
        echo "ERROR: KEEN_PBR_FRONTEND_DIST_MODE must be 'source' or 'prebuilt'." >&2
        exit 1
        ;;
esac

sh "$WORKSPACE/build_scripts/build-frontend.sh" "$WORKSPACE" "$DIST_DIR"

ACTUAL_ID="$(cat "$MARKER" 2>/dev/null || true)"
if [ ! -s "$DIST_DIR/index.html" ] || [ "$ACTUAL_ID" != "$EXPECTED_ID" ]; then
    echo "ERROR: frontend build did not produce a verified bundle: $DIST_DIR" >&2
    exit 1
fi

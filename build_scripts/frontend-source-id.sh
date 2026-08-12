#!/bin/sh

set -eu

WORKSPACE="${1:?Usage: $0 <workspace-dir>}"
FRONTEND_DIR="$WORKSPACE/frontend"

if [ ! -d "$FRONTEND_DIR" ] || [ ! -f "$WORKSPACE/version.mk" ]; then
    echo "ERROR: frontend sources or version.mk are missing from $WORKSPACE." >&2
    exit 1
fi

for tool in cksum find mktemp sort; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "ERROR: $tool is required to fingerprint frontend sources." >&2
        exit 1
    fi
done

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/keen-pbr-frontend-id.XXXXXX")"
trap 'rm -rf "$TMP_ROOT"' EXIT HUP INT TERM

(
    cd "$WORKSPACE"
    find frontend -type f \
        ! -path 'frontend/dist/*' \
        ! -path 'frontend/node_modules/*' \
        -print
    if [ -d logos ]; then
        find logos -type f -print
    fi
    printf '%s\n' \
        build_scripts/build-frontend.sh \
        build_scripts/frontend-source-id.sh \
        version.mk
) > "$TMP_ROOT/files.unsorted"

LC_ALL=C sort "$TMP_ROOT/files.unsorted" > "$TMP_ROOT/files"

(
    cd "$WORKSPACE"
    while IFS= read -r path; do
        [ -f "$path" ] || {
            echo "ERROR: frontend input disappeared while fingerprinting: $path" >&2
            exit 1
        }
        set -- $(cksum < "$path")
        printf '%s %s %s\n' "$1" "$2" "$path"
    done < "$TMP_ROOT/files"
) > "$TMP_ROOT/manifest"

set -- $(cksum < "$TMP_ROOT/manifest")
printf 'cksum-v1:%s:%s\n' "$1" "$2"

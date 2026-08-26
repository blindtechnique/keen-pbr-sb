#!/usr/bin/env bash

set -euo pipefail

MODE="${1:?Usage: $0 <version|release|full|commit> <workspace-dir>}"
WORKSPACE="${2:?}"

. "$WORKSPACE/version.mk"

resolve_release() {
    if [ -n "${KEEN_PBR_RELEASE_OVERRIDE:-}" ]; then
        printf '%s' "$KEEN_PBR_RELEASE_OVERRIDE"
        return
    fi

    if command -v git >/dev/null 2>&1 && git -C "$WORKSPACE" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        TZ=UTC git -C "$WORKSPACE" log -1 --format=%cd --date=format-local:%Y%m%d%H%M%S
        return
    fi

    # Exported source trees have no commit timestamp. Generate a real build
    # identity instead of reviving the historical numeric release counter.
    TZ=UTC date '+%Y%m%d%H%M%S'
}

validate_commit() {
    local value="$1"
    local base length

    if [ "$value" = "unknown" ]; then
        return 0
    fi

    base="${value%-dirty}"
    case "$base" in
        ''|*[!0-9a-f]*)
            echo "Invalid KEEN_PBR commit identity: $value" >&2
            return 1
            ;;
    esac
    length=${#base}
    if [ "$length" -lt 12 ] || [ "$length" -gt 64 ]; then
        echo "Invalid KEEN_PBR commit identity length: $value" >&2
        return 1
    fi
    if [ "$value" != "$base" ] && [ "$value" != "$base-dirty" ]; then
        echo "Invalid KEEN_PBR commit identity suffix: $value" >&2
        return 1
    fi
}

resolve_commit() {
    local commit dirty

    if [ -n "${KEEN_PBR_COMMIT_OVERRIDE:-}" ]; then
        validate_commit "$KEEN_PBR_COMMIT_OVERRIDE"
        printf '%s' "$KEEN_PBR_COMMIT_OVERRIDE"
        return
    fi

    if command -v git >/dev/null 2>&1 &&
       git -C "$WORKSPACE" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        commit="$(git -C "$WORKSPACE" rev-parse --short=12 HEAD 2>/dev/null || true)"
        if [ -n "$commit" ]; then
            # Failure to inspect the worktree must never be reported as a
            # verified clean commit. Conservatively mark it dirty instead.
            if dirty="$(git -C "$WORKSPACE" status --porcelain --untracked-files=normal 2>/dev/null)"; then
                if [ -n "$dirty" ]; then
                    commit="$commit-dirty"
                fi
            else
                commit="$commit-dirty"
            fi
            validate_commit "$commit"
            printf '%s' "$commit"
            return
        fi
    fi

    printf 'unknown'
}

case "$MODE" in
    version)
        printf '%s' "$KEEN_PBR_VERSION"
        ;;
    release)
        resolve_release
        ;;
    full)
        printf '%s-%s' "$KEEN_PBR_VERSION" "$(resolve_release)"
        ;;
    commit)
        resolve_commit
        ;;
    *)
        echo "Unknown mode: $MODE" >&2
        exit 1
        ;;
esac

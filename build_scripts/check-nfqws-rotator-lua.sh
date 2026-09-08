#!/usr/bin/env sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
lua_bin=${LUA_BIN:-}

if [ -z "$lua_bin" ]; then
    for candidate in luajit lua5.4 lua5.3 lua; do
        if command -v "$candidate" >/dev/null 2>&1; then
            lua_bin=$candidate
            break
        fi
    done
fi

if [ -z "$lua_bin" ]; then
    echo "ERROR: LuaJIT or Lua 5.3+ is required for the nfqws telemetry smoke" >&2
    exit 1
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/keen-pbr-nfqws-lua.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM

fixture="$repo_root/tests/fixtures/zapret2-v1.0.3"
(cd "$fixture" && sha256sum -c SHA256SUMS)

WRITABLE=$work "$lua_bin" \
    "$repo_root/tests/nfqws_rotator_telemetry_smoke.lua" \
    "$repo_root/packages/keenetic/keen-pbr/files/opt/usr/share/keen-pbr/nfqws-lua/rotator-telemetry.lua"

"$lua_bin" \
    "$repo_root/tests/nfqws_rotator_memory_bound.lua" \
    "$repo_root/packages/keenetic/keen-pbr/files/opt/usr/share/keen-pbr/nfqws-lua/rotator-telemetry.lua"

WRITABLE=$work \
KEEN_PBR_NFQWS_ROTATOR_LEARNED_PREFIX="$work/nfqws-rotator-learned-v1" \
"$lua_bin" \
    "$repo_root/tests/nfqws_rotator_persistence_smoke.lua" \
    "$repo_root/packages/keenetic/keen-pbr/files/opt/usr/share/keen-pbr/nfqws-lua/rotator-telemetry.lua" \
    "$fixture/zapret-auto.lua"

"$lua_bin" \
    "$repo_root/tests/nfqws_circular_v103_semantics.lua" \
    "$fixture/zapret-auto.lua" \
    "$fixture/zapret-lib-is-retransmission.lua"

"$lua_bin" \
    "$repo_root/tests/nfqws_legacy_udp_pool_semantics.lua" \
    "$fixture/zapret-auto.lua" \
    "$repo_root/packages/keenetic/keen-pbr/files/opt/usr/share/keen-pbr/nfqws-strategies"

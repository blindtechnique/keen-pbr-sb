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

WRITABLE=$work "$lua_bin" \
    "$repo_root/tests/nfqws_rotator_telemetry_smoke.lua" \
    "$repo_root/packages/keenetic/keen-pbr/files/opt/usr/share/keen-pbr/nfqws-lua/rotator-telemetry.lua"

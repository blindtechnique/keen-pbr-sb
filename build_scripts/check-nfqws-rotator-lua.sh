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

"$lua_bin" \
    "$repo_root/tests/nfqws_rotator_memory_bound.lua" \
    "$repo_root/packages/keenetic/keen-pbr/files/opt/usr/share/keen-pbr/nfqws-lua/rotator-telemetry.lua"

check_fixture() {
    fixture="$repo_root/tests/fixtures/$1"
    fixture_work="$work/$1"
    mkdir "$fixture_work"
    echo "nfqws Lua regression: $1"
    (cd "$fixture" && sha256sum -c SHA256SUMS)

    WRITABLE=$fixture_work \
    KEEN_PBR_NFQWS_ROTATOR_LEARNED_PREFIX="$fixture_work/nfqws-rotator-learned-v1" \
    "$lua_bin" \
        "$repo_root/tests/nfqws_rotator_persistence_smoke.lua" \
        "$repo_root/packages/keenetic/keen-pbr/files/opt/usr/share/keen-pbr/nfqws-lua/rotator-telemetry.lua" \
        "$fixture/zapret-auto.lua" \
        "$fixture/zapret-lib-host-ip.lua"

    "$lua_bin" \
        "$repo_root/tests/nfqws_circular_v103_semantics.lua" \
        "$fixture/zapret-auto.lua" \
        "$fixture/zapret-lib-is-retransmission.lua"

    "$lua_bin" \
        "$repo_root/tests/nfqws_legacy_udp_pool_semantics.lua" \
        "$fixture/zapret-auto.lua" \
        "$repo_root/packages/keenetic/keen-pbr/files/opt/usr/share/keen-pbr/nfqws-strategies"

    "$lua_bin" \
        "$repo_root/tests/nfqws_video_tcp_semantics.lua" \
        "$fixture" \
        "$repo_root/packages/keenetic/keen-pbr/files/opt/usr/share/keen-pbr/nfqws-strategies" \
        "$repo_root/packages/keenetic/keen-pbr/files/opt/usr/share/keen-pbr/nfqws-lua/rotator-telemetry.lua"

    "$lua_bin" \
        "$repo_root/tests/nfqws_discord_pool_semantics.lua" \
        "$fixture" \
        "$repo_root/packages/keenetic/keen-pbr/files/opt/usr/share/keen-pbr/nfqws-strategies" \
        "$repo_root/packages/keenetic/keen-pbr/files/opt/usr/share/keen-pbr/nfqws-lua/rotator-telemetry.lua"

    "$lua_bin" \
        "$repo_root/tests/nfqws_tcp_syn_semantics.lua" \
        "$fixture" \
        "$repo_root/packages/keenetic/keen-pbr/files/opt/usr/share/keen-pbr/nfqws-lua/rotator-telemetry.lua" \
        "$repo_root/packages/keenetic/keen-pbr/files/opt/usr/share/keen-pbr/nfqws-strategies"

    "$lua_bin" \
        "$repo_root/tests/nfqws_tcp_success_semantics.lua" \
        "$fixture" \
        "$repo_root/packages/keenetic/keen-pbr/files/opt/usr/share/keen-pbr/nfqws-lua/rotator-telemetry.lua"

    "$lua_bin" \
        "$repo_root/tests/nfqws_tcp_tls_failure_semantics.lua" \
        "$fixture" \
        "$repo_root/packages/keenetic/keen-pbr/files/opt/usr/share/keen-pbr/nfqws-lua/rotator-telemetry.lua" \
        "$repo_root/packages/keenetic/keen-pbr/files/opt/usr/share/keen-pbr/nfqws-strategies"

    "$lua_bin" \
        "$repo_root/tests/nfqws_rotator_trace_semantics.lua" \
        "$fixture" \
        "$repo_root/packages/keenetic/keen-pbr/files/opt/usr/share/keen-pbr/nfqws-lua/rotator-telemetry.lua" \
        "$repo_root/build_scripts/diagnostics/nfqws-rotator-trace.lua" \
        "$repo_root/packages/keenetic/keen-pbr/files/opt/usr/share/keen-pbr/nfqws-strategies"
}

check_fixture zapret2-v1.0.3
check_fixture zapret2-v1.0.5.2

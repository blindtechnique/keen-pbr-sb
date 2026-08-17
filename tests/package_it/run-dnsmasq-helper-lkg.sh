#!/bin/sh

set -eu

[ "$#" -gt 0 ] || {
    echo "usage: $0 <dnsmasq-helper> [...]" >&2
    exit 2
}

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT HUP INT TERM

fake_bin="${workdir}/keen-pbr"
state_dir="${workdir}/state"
fallback_file="${workdir}/fallback.conf"

cat > "$fake_bin" <<'EOF'
#!/bin/sh
case "${FAKE_RESOLVER_MODE:-good}" in
    good)
        printf '# keen-pbr resolver state: active\ntxt-record=config-hash.keen.pbr,1|0123456789abcdef0123456789abcdef\nserver=1.1.1.1\ntxt-record=resolver-state.keen.pbr,1|active|runtime_active\n'
        ;;
    partial)
        printf '# keen-pbr resolver state: active\ntxt-record=config-hash.keen.pbr,1|0123456789abcdef0123456789abcdef\nserver=9.9.9.9\n'
        exit 1
        ;;
    invalid)
        printf '# keen-pbr resolver state: active\ntxt-record=config-hash.keen.pbr,1|0123456789abcdef0123456789abcdef\nserver=9.9.9.9\n'
        ;;
    fallback)
        printf '# keen-pbr resolver state: fallback reason=socket_unavailable\ntxt-record=resolver-state.keen.pbr,1|fallback|socket_unavailable\nserver=8.8.4.4\n'
        ;;
    failed)
        exit 1
        ;;
    *)
        exit 2
        ;;
esac
EOF
chmod 700 "$fake_bin"
printf 'server=8.8.8.8\n' > "$fallback_file"

for helper in "$@"; do
    rm -rf "$state_dir"
    mkdir -p "$state_dir"
    printf 'Y\n' > "${state_dir}/active"

    common_env="KEEN_PBR_BIN=${fake_bin} KEEN_PBR_STATE_DIR=${state_dir} KEEN_PBR_DNSMASQ_FALLBACK_FILE=${fallback_file}"

    output="$(
        env $common_env FAKE_RESOLVER_MODE=good \
            /bin/sh "$helper" dnsmasq-config-entry
    )"
    printf '%s\n' "$output" | grep -q '^server=1\.1\.1\.1$'

    output="$(
        env $common_env FAKE_RESOLVER_MODE=partial \
            /bin/sh "$helper" dnsmasq-config-entry
    )"
    printf '%s\n' "$output" | grep -q '^server=1\.1\.1\.1$'
    if printf '%s\n' "$output" | grep -q '^server=9\.9\.9\.9$'; then
        echo "$helper exposed a partial resolver generation" >&2
        exit 1
    fi

    output="$(
        env $common_env FAKE_RESOLVER_MODE=invalid \
            /bin/sh "$helper" dnsmasq-config-entry
    )"
    printf '%s\n' "$output" | grep -q '^server=1\.1\.1\.1$'

    output="$(
        env $common_env FAKE_RESOLVER_MODE=fallback \
            /bin/sh "$helper" dnsmasq-config-entry
    )"
    printf '%s\n' "$output" | grep -q '^server=8\.8\.4\.4$'
    if printf '%s\n' "$output" | grep -q '^server=1\.1\.1\.1$'; then
        echo "$helper ignored a complete resolver fallback" >&2
        exit 1
    fi

    rm -f "${state_dir}/dnsmasq-managed.conf"
    output="$(
        env $common_env FAKE_RESOLVER_MODE=fallback \
            /bin/sh "$helper" dnsmasq-config-entry
    )"
    printf '%s\n' "$output" | grep -q '^server=8\.8\.4\.4$'

    rm -f "${state_dir}/dnsmasq-managed.conf"
    output="$(
        env $common_env FAKE_RESOLVER_MODE=failed \
            /bin/sh "$helper" dnsmasq-config-entry
    )"
    printf '%s\n' "$output" |
        grep -q "^conf-file=${fallback_file}$"

    rm -f "${state_dir}/dnsmasq-managed.conf"
    output="$(
        env $common_env FAKE_RESOLVER_MODE=invalid \
            /bin/sh "$helper" dnsmasq-config-entry
    )"
    printf '%s\n' "$output" |
        grep -q "^conf-file=${fallback_file}$"
    if printf '%s\n' "$output" | grep -q '^server=9\.9\.9\.9$'; then
        echo "$helper exposed a successful but incomplete resolver generation" >&2
        exit 1
    fi
done

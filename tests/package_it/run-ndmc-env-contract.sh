#!/bin/sh
#
# The Keenetic CLI must never inherit Entware's LD_LIBRARY_PATH: /opt/lib holds
# Entware's own glibc and ndmc then dies in Cli::Main before it runs anything.
# check-shell-busybox.sh proves the *shape* of every call site; this proves the
# *behaviour* of the helper those call sites go through, against the shipped
# scripts themselves rather than a copy of them.

set -eu

[ "$#" -gt 0 ] || {
    echo "usage: $0 <script-with-run_ndmc> [...]" >&2
    exit 2
}

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT HUP INT TERM

# Stands in for /bin/ndmc. It records the environment it was actually given and
# can reproduce the real failure: the firmware reports the broken load on
# stdout, not stderr, with a non-zero exit.
cat > "${workdir}/ndmc" <<'EOF'
#!/bin/sh
printf '%s' "${LD_LIBRARY_PATH-UNSET}" > "${NDMC_SEEN_LD_LIBRARY_PATH}"
printf '%s' "$*" > "${NDMC_SEEN_ARGS}"
if [ "${NDMC_FAIL:-0}" = "1" ]; then
    echo "[C] ndm: ndmc: system failed [0xcffd0062]."
    echo "[C] ndm: Cli::Main: failed to initialize."
    exit 7
fi
echo "ok"
EOF
chmod +x "${workdir}/ndmc"
PATH="${workdir}:${PATH}"
export PATH

NDMC_SEEN_LD_LIBRARY_PATH="${workdir}/seen-ld"
NDMC_SEEN_ARGS="${workdir}/seen-args"
export NDMC_SEEN_LD_LIBRARY_PATH NDMC_SEEN_ARGS

failures=0

fail() {
    echo "FAIL: $*" >&2
    failures=$((failures + 1))
}

for script in "$@"; do
    [ -f "$script" ] || { fail "$script: not a file"; continue; }

    definition="$(sed -n '/^run_ndmc() {/,/^}/p' "$script")"
    if [ -z "$definition" ]; then
        fail "$script: no top-level run_ndmc() definition to test"
        continue
    fi

    echo "== $script =="

    # install.sh routes messages through say(); uninstall.sh uses echo. Provide
    # the one that may be missing so the shipped body runs unmodified.
    say() { printf '%s\n' "$*"; }
    eval "$definition"

    # A poisoned parent environment is the whole point of the exercise.
    LD_LIBRARY_PATH=/opt/lib
    export LD_LIBRARY_PATH

    : > "$NDMC_SEEN_LD_LIBRARY_PATH"
    : > "$NDMC_SEEN_ARGS"
    NDMC_FAIL=0
    export NDMC_FAIL

    if run_ndmc "system configuration save" > "${workdir}/out" 2> "${workdir}/err"; then
        :
    else
        fail "$script: a successful call reported failure"
    fi

    seen="$(cat "$NDMC_SEEN_LD_LIBRARY_PATH")"
    [ -z "$seen" ] || fail "$script: child saw LD_LIBRARY_PATH='$seen', expected it empty"

    seen_args="$(cat "$NDMC_SEEN_ARGS")"
    [ "$seen_args" = "-c system configuration save" ] ||
        fail "$script: child got args '$seen_args'"

    [ "${LD_LIBRARY_PATH-}" = "/opt/lib" ] ||
        fail "$script: the caller's own LD_LIBRARY_PATH was modified"

    [ ! -s "${workdir}/out" ] ||
        fail "$script: a successful call must stay quiet on stdout"
    [ ! -s "${workdir}/err" ] ||
        fail "$script: a successful call must stay quiet on stderr"

    # Failure path: ndmc prints its diagnostic on stdout, so a helper that
    # discarded stdout would leave the operator with nothing to read.
    NDMC_FAIL=1
    export NDMC_FAIL
    status=0
    run_ndmc "opkg dns-override" > "${workdir}/out" 2> "${workdir}/err" || status=$?

    [ "$status" = "7" ] ||
        fail "$script: expected the CLI exit code 7 to propagate, got '$status'"
    grep -q "failed to initialize" "${workdir}/err" ||
        fail "$script: the failure diagnostic never reached stderr"
    [ ! -s "${workdir}/out" ] ||
        fail "$script: the diagnostic must go to stderr, not stdout"

    unset LD_LIBRARY_PATH
    unset -f run_ndmc 2>/dev/null || true
done

if [ "$failures" -ne 0 ]; then
    echo "ndmc env contract: $failures problem(s)" >&2
    exit 1
fi
echo "ndmc env contract: OK"

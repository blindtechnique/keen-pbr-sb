#!/usr/bin/env bash
# Local/CI development runner. No daemon, sing-box, router or network calls.
set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root/extensions/transport-manager"

fuzz_time=${GO_FUZZ_TIME:-30s}
fuzz_parallel=${GO_FUZZ_PARALLEL:-2}
fuzz_timeout=${GO_FUZZ_TIMEOUT:-3m}
fuzz_target=${GO_FUZZ_TARGET:-all}

# Reject an accidental unbounded (0) run. These are test-runner budgets only,
# never application validation limits. Explicit longer campaigns are opt-in.
if [[ ! $fuzz_time =~ ^[1-9][0-9]*(ms|s|m|h|x)$ ]] ||
   [[ ! $fuzz_timeout =~ ^[1-9][0-9]*(s|m|h)$ ]] ||
   [[ ! $fuzz_parallel =~ ^[1-8]$ ]]; then
    printf '%s\n' 'Use positive GO_FUZZ_TIME (e.g. 30s or 100x), GO_FUZZ_TIMEOUT (e.g. 3m), GO_FUZZ_PARALLEL (1..8).' >&2
    exit 2
fi
case "$fuzz_target" in
    all|FuzzShareLink|FuzzBase64Payload|FuzzTransportConfig|FuzzTransportInput) ;;
    *) printf '%s\n' 'Unknown GO_FUZZ_TARGET; see docs/GO_FUZZING.ru.md.' >&2; exit 2 ;;
esac

export GOMAXPROCS=${GOMAXPROCS:-$fuzz_parallel}
export GOMEMLIMIT=${GOMEMLIMIT:-256MiB}
export GOCACHE=${GOCACHE:-$repo_root/build/go-fuzz-cache}
export GOTOOLCHAIN=${GOTOOLCHAIN:-local}
mkdir -p "$GOCACHE"

for target in FuzzShareLink FuzzBase64Payload FuzzTransportConfig FuzzTransportInput; do
    if [[ $fuzz_target != all && $fuzz_target != "$target" ]]; then
        continue
    fi
    package=./internal/transport
    if [[ $target == FuzzTransportInput ]]; then
        package=./internal/api
    fi
    # go test can succeed when a selection matches nothing; do not report that
    # as fuzz coverage if a target was renamed or accidentally removed.
    names=$(go test "$package" -list "^${target}$")
    if ! printf '%s\n' "$names" | grep -qx "$target"; then
        printf 'Fuzz target missing: %s\n' "$target" >&2
        exit 1
    fi
    printf 'Go fuzz: %s, budget=%s, workers=%s\n' "$target" "$fuzz_time" "$fuzz_parallel"
    go test "$package" -run '^$' -fuzz "^${target}$" \
        -fuzztime "$fuzz_time" -fuzzminimizetime 5s \
        -parallel "$fuzz_parallel" -timeout "$fuzz_timeout"
done

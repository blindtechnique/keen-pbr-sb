# zapret2 v1.0.3 semantic test fixture

This directory is test-only. None of these upstream files is installed or
included in the keen-pbr-sb runtime package.

- Upstream: https://github.com/bol-van/zapret2
- Tag: `v1.0.3`
- Commit: `b78b52c4cd7f843da3ff0848a3430afbd401bdf2`
- License: MIT, reproduced in `LICENSE.MIT`

`zapret-auto.lua` is an unmodified copy from that tag. Its SHA-256 is
`aacfde0c95c3058f8e95f5d7d244398bdc03ebf846a8f17322129fb543366a3d`.

`zapret-lib-is-retransmission.lua` is the exact, unmodified function at
`lua/zapret-lib.lua:388-390` from the same tag. The complete upstream
`zapret-lib.lua` has SHA-256
`2740b1bc0e728c4283846df94783844082eabd503ce1f86e3429159e1b4e8de3`.
Only this function is needed by the bounded semantic harness, so the remaining
92 KiB library is not vendored.

The harness supplies deterministic stand-ins for nfqws execution-plan,
packet-position and logging primitives. The circular orchestrator, failure and
success detectors, per-host/per-connection state, and retransmission predicate
under test are the pinned upstream code above.

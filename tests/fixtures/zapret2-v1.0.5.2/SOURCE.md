# zapret2 v1.0.5.2 / nfqws2-keenetic 1.3.1 semantic fixture

Test-only files; these Lua copies are not installed in the runtime package.

- Upstream: https://github.com/bol-van/zapret2/tree/v1.0.5.2
- Commit: `6b6c63e3385fa73f8af3be4a69171e947f5a319d`
- License: upstream `docs/LICENSE.txt`, reproduced as `LICENSE.MIT`.
- Distribution: https://github.com/nfqws/nfqws2-keenetic/releases/tag/v1.3.1
- Official `nfqws2-keenetic_1.3.1_all_entware.ipk` SHA-256:
  `28af67f8e192c838e007f23517b52b1f8c20d030cef5b971dfc93b7f21a79054`.

`zapret-auto.lua` is the complete unmodified upstream file. Its bytes also
match the decompressed `opt/etc/nfqws2/lua/zapret-auto.lua.gz` in that package.
The corresponding complete `zapret-lib.lua` matches upstream too; its SHA-256
is `b67a470f23b00a8d6e732c4e5135a39b224511e0b71809d5f4616adf62674980`.
Only its verbatim `is_retransmission` and `host_ip` functions are needed by
the deterministic harnesses and retained here. Both match the older v1.0.3
helpers. `SHA256SUMS` pins every Lua file before execution.

The shared harnesses supply packet-position, logging, and execution-plan
primitives. They exercise upstream circular orchestration and our companion,
not Keenetic hardware fastpath or the C-engine TLS reassembly patch. Keep the
v1.0.3 fixture alongside this one to retain the older-package regression gate.

# Historical config migration fixtures

These are small synthetic configurations, not router exports or byte-for-byte
release samples. Tags, domains, interface names and addresses are test values.
No file, hook, resolver or interface is executed by these parser tests. The
single-outbound routing rule is current-compatible synthetic boilerplate; these
fixtures do not claim support for removed historical routing fallback fields.

Verified format provenance from local Git history:

| Fixture | Historical evidence |
| --- | --- |
| `pre-hex-fwmark.json` | Parent of `1535b6abe1c4c704ec46ec5fde36a807d672f79f` (2026-03-28): `config.example.json` used integer `fwmark.start: 65536` and `mask: 16711680`; that commit changed both to hexadecimal strings. `beed014b50a550a0874685f995ed5f3eee89ab3c` (2026-04-04) changed `dns.fallback` from a string to an ordered string array. |
| `pre-dns-probe-rename.json` | `3917dada666a55ba0df30f333338a770a5ef806a` (2026-03-12) added `dns.test_server` to both the example and parser. `2494c0abc9388d5736d26190c44f4cd3be01c403` (2026-03-15) renamed the typed/parser field to `dns.dns_test_server`; `feee7605c3540ad5a4a4d2825dcb811009511fe1` later fixed the documentation. The current required `system_resolver.address` is test boilerplate added to this early format so the fixture also exercises complete current validation. |
| `sb3-unversioned-modern.json` | `1c37584bd7944e6a36fc4b3c1a0fa64342163fc1` (`3.0.7-sb.3`, 2026-07-18), `packages/common/config.full.example.json`: no schema marker, hexadecimal fwmarks, array DNS fallback, canonical `dns_test_server`. The fixture keeps those shapes and supplies a synthetic VPN/list/rule for round-trip assertions. |

All three must migrate to the current schema without changing the selected
route, DNS server, mark value or DNS probe settings. Unknown fields survive the
raw migration boundary and ordinary typed load/save, including opaque nulls and
empty containers. This does not implement runtime semantics for unknown fields.
A non-null canonical `dns_test_server` takes precedence over
the legacy alias, which remains present in raw JSON without gaining precedence.

Explicit current-version configurations are not reinterpreted as legacy input.
Negative, fractional, boolean or out-of-range numeric fwmarks are not coerced.
Historical route failover arrays and removed resolver hooks are deliberately not
re-created: this slice does not invent replacement runtime semantics.

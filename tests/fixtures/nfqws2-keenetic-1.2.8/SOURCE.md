# Stock strategy reference

`packages/keenetic/keen-pbr/files/opt/usr/share/keen-pbr/nfqws-strategies/default (nfqws2 1.2.8)/nfqws2.conf`
is the unmodified configuration from the official package:
https://github.com/nfqws/nfqws2-keenetic/releases/download/v1.2.8/nfqws2-keenetic_1.2.8_aarch64-3.10.ipk

Configuration SHA-256: b5c6598d5ba03762393a877514e005d2a241e0eb51c4e03142cade544e1e5b30.
The `all_entware` package contains the same configuration.
The package postinst detects ISP_INTERFACE and IPV6_ENABLED. With only
IPV6_ENABLED=0, SHA-256 is 3ee6bc9484d90e536b20acf810c6fdab3d8b2b227b4e54b0d67c7268fa6cd7fc,
exactly matching the user's untouched Giga installation on 2026-09-17.

This is a separate stock reference, not a replacement for our legacy
`default` preset or the Safe/Balanced/Max presets. Reading status does not
write or apply this configuration to the router.

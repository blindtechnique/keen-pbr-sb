# Stock strategy reference

`packages/keenetic/keen-pbr/files/opt/usr/share/keen-pbr/nfqws-strategies/default (nfqws2 1.3.1)/nfqws2.conf`
is the unmodified configuration from the official package:
https://github.com/nfqws/nfqws2-keenetic/releases/download/v1.3.1/nfqws2-keenetic_1.3.1_aarch64-3.10.ipk

- Package SHA-256: `9167d72053a83a78f48f6439af38432fb2d1d411fb22c0980240a949ace614df`.
- Configuration SHA-256: `b994f88b865d9a42275f8201f9ec55f2b22b16d8ac3942d0c71f677de4d1b7c5`.
- Source: https://github.com/nfqws/nfqws2-keenetic/tree/v1.3.1
- License: the upstream MIT license is included beside the packaged reference.

The `all_entware` package contains the same configuration. Postinst may adapt
ISP_INTERFACE and IPV6_ENABLED to the router. Strategy recognition tolerates
only the existing runtime adaptations, not a changed fastpath mode or policy.

This reference is separate from legacy `default`, the 1.2.8 reference, and
Safe/Balanced/Max. Reading status does not apply it or change a router's saved
configuration. On 1.3.1, the vendor init supplies `--fastpath-workaround=auto`
when the saved NFQWS_BASE_ARGS do not contain an explicit mode. Keeping our
generated presets unchanged also preserves compatibility with older binaries.

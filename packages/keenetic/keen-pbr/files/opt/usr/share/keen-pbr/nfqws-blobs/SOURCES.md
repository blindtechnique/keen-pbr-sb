# nfqws blob provenance

Twenty blobs in this directory come from
[`Necronicle/z2k`](https://github.com/Necronicle/z2k) commit
`ee2d04a5554dea26bbded45416e13e590bb71c6c`, directory `files/fake/`, under
the MIT license preserved at `third_party/z2k/LICENSE.MIT`.

The package uses descriptive target names for three upstream files:

- `quic_4.bin`, `quic_5.bin`, `quic_6.bin` become
  `quic_initial_4.bin`, `quic_initial_5.bin`, `quic_initial_6.bin`;
- `t2.bin` becomes `tls_clienthello_t2.bin`.

The pre-existing `quic_initial_steamcommunity_com.bin` is maintained by this
project and is not attributed to z2k. Its bytes are pinned alongside the z2k
files in `ORIGIN_SHA256SUMS`.

`http_iana_org.bin` is an HTTP packet fixture. Its 427-byte origin contains
CRLF line endings and must stay binary; LF normalization changes both the
protocol bytes and its pinned SHA-256
`3e4fb49b1323ddf2f8e691b1cbe804207b4e849711d76f79ebf2b54247a9285e`.

The upstream duplicates `4pda.bin` and `quic_1.bin`, and the unrelated
`quic_test_00.bin`, are intentionally not shipped. Stock `quic_initial.bin`
and `tls_clienthello.bin` remain owned by the installed nfqws2 package.

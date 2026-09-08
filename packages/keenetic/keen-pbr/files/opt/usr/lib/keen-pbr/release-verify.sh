#!/bin/sh
# Standalone verification before any downloaded installer/package is executed.
# The caller supplies an already trusted public key, never a downloaded one.
set -eu
LC_ALL=C
export LC_ALL

release_verify_fail() {
    printf '%s\n' "Release verification failed: $*" >&2
    exit 1
}

[ "$#" -eq 11 ] || release_verify_fail 'invalid arguments'
rv_manifest=$1
rv_signature=$2
rv_key=$3
rv_repository=$4
rv_channel=$5
rv_release=$6
rv_kind=$7
rv_arch=$8
rv_abi=$9
shift 9
rv_filename=$1
rv_localfile=$2

# Restrict context before passing it through awk -v (which interprets escapes).
case "$rv_repository" in ''|*[!A-Za-z0-9_./-]*) release_verify_fail 'invalid repository' ;; esac
case "$rv_channel" in stable|alpha|next) ;; *) release_verify_fail 'invalid channel' ;; esac
case "$rv_release" in ''|*[!A-Za-z0-9._-]*) release_verify_fail 'invalid release' ;; esac
case "$rv_kind" in installer|package) ;; *) release_verify_fail 'invalid file kind' ;; esac
case "$rv_arch" in any|aarch64|armv7|mipsel|mips|x64) ;; *) release_verify_fail 'invalid architecture' ;; esac
case "$rv_abi" in ''|*[!0-9.a-z]*) release_verify_fail 'invalid ABI' ;; esac
case "$rv_filename" in ''|*[!A-Za-z0-9._+-]*) release_verify_fail 'invalid filename' ;; esac

# Prevent an option-like relative path from being interpreted by OpenSSL.
case "$rv_manifest" in /*|./*|../*) ;; *) rv_manifest=./$rv_manifest ;; esac
case "$rv_signature" in /*|./*|../*) ;; *) rv_signature=./$rv_signature ;; esac
case "$rv_key" in /*|./*|../*) ;; *) rv_key=./$rv_key ;; esac
case "$rv_localfile" in /*|./*|../*) ;; *) rv_localfile=./$rv_localfile ;; esac
for rv_input in "$rv_manifest" "$rv_signature" "$rv_key" "$rv_localfile"; do
    [ -f "$rv_input" ] && [ -r "$rv_input" ] || release_verify_fail 'a required file is unavailable'
done
rv_bytes=$(wc -c < "$rv_manifest")
[ "$rv_bytes" -gt 0 ] && [ "$rv_bytes" -le 65536 ] || release_verify_fail 'manifest size is invalid'
rv_bytes=$(wc -c < "$rv_signature")
[ "$rv_bytes" -eq 384 ] || release_verify_fail 'signature size is invalid'
# The marker keeps command substitution from stripping the final LF. Keenetic's
# small od applet does not support -A/-t; no byte-dump options are needed here.
rv_last_byte=$(tail -c 1 "$rv_manifest"; printf '.')
[ "$rv_last_byte" = "$(printf '\n.')" ] || release_verify_fail 'manifest must end with LF'

if [ -x /opt/bin/openssl ]; then
    rv_openssl=/opt/bin/openssl
elif command -v openssl >/dev/null 2>&1; then
    rv_openssl=$(command -v openssl)
else
    release_verify_fail 'OpenSSL is unavailable'
fi
"$rv_openssl" dgst -sha256 -verify "$rv_key" -sigopt rsa_padding_mode:pkcs1 \
    -signature "$rv_signature" "$rv_manifest" \
    >/dev/null 2>&1 || release_verify_fail 'signature is invalid'

rv_expected=$(awk -F '\t' \
    -v repository="$rv_repository" -v channel="$rv_channel" -v release="$rv_release" \
    -v kind="$rv_kind" -v arch="$rv_arch" -v abi="$rv_abi" -v filename="$rv_filename" '
function fail() { invalid = 1; exit 1 }
function token(value) {
    return length(value) <= 128 && value ~ /^[A-Za-z0-9][A-Za-z0-9._-]*$/
}
function hex(value, size) {
    return length(value) == size && value ~ /^[0-9a-f]+$/
}
index($0, "\r") { fail() }
NR == 1 { if (NF != 1 || $0 != "keen-pbr-release-v1") fail(); next }
NR == 2 {
    if (NF != 2 || $1 != "repository" || length($2) > 160 ||
        $2 !~ /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/ || $2 != repository) fail()
    next
}
NR == 3 { if (NF != 2 || $1 != "channel" || $2 != channel) fail(); next }
NR == 4 { if (NF != 2 || $1 != "release" || !token($2) || $2 != release) fail(); next }
NR == 5 { if (NF != 2 || $1 != "source" || !hex($2, 40)) fail(); next }
NR == 6 { if (NF != 2 || $1 != "build" || !token($2)) fail(); next }
{
    if (NF != 7 || $1 != "file" || ++files > 32 || !hex($6, 64) ||
        length($7) > 255 || $7 !~ /^[A-Za-z0-9][A-Za-z0-9._+-]*$/ || names[$7]++) fail()
    if ($2 == "installer") {
        if ($3 != "any" || $4 != "any" || $5 != "-" || $7 != "install.sh" || ++installers > 1) fail()
    } else if ($2 == "package") {
        if ($3 !~ /^(aarch64|armv7|mipsel|mips|x64)$/ || $4 !~ /^[0-9]+(\.[0-9]+)*$/ ||
            length($5) > 128 || $5 !~ /^[A-Za-z0-9][A-Za-z0-9._+-]*$/ ||
            $7 != "keen-pbr_" $5 "_keenetic_" $3 "-" $4 ".ipk" || targets[$3 "/" $4]++) fail()
        packages++
    } else fail()
    if ($2 == kind && $3 == arch && $4 == abi && $7 == filename) {
        selected++
        expected = $6
    }
}
END {
    if (invalid || installers != 1 || packages < 1 || selected != 1) exit 1
    print expected
}' "$rv_manifest") || release_verify_fail 'manifest context or file inventory is invalid'

if command -v sha256sum >/dev/null 2>&1; then
    rv_actual=$(sha256sum "$rv_localfile") || release_verify_fail 'file hashing failed'
elif command -v busybox >/dev/null 2>&1; then
    rv_actual=$(busybox sha256sum "$rv_localfile") || release_verify_fail 'file hashing failed'
else
    release_verify_fail 'SHA256 is unavailable'
fi
rv_actual=${rv_actual%% *}
[ "$rv_actual" = "$rv_expected" ] || release_verify_fail 'file checksum does not match the signed manifest'

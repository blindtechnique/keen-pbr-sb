#!/bin/sh
# Focused regression: postinst context must end before rc.func spawns daemons.
set -eu
source_root=${1:?source root required}
files=$source_root/packages/keenetic/keen-pbr/files
work=$(mktemp -d /tmp/kpbr-start-environment.XXXXXX)
trap 'rm -rf "$work"' 0 HUP INT TERM
mkdir -p "$work/opt/etc/init.d" "$work/opt/usr/lib/keen-pbr"

# S79 uses its complete production dispatcher; only the external guard and
# process launcher are replaced. S80's final pre-launch block is shared with
# its actual dispatcher and does not need a simulated router/firewall.
sed "s#/opt/#$work/opt/#g" "$files/opt/etc/init.d/S79transport-manager" > "$work/S79"
printf '#!/bin/sh\n[ "${KEEN_PBR_PACKAGE_POSTINST:-}" = 1 ]\n' > "$work/opt/etc/init.d/S00keen-pbr-rescue"
chmod 700 "$work/opt/etc/init.d/S00keen-pbr-rescue"
printf '%s\n' \
  'for flag in KEEN_PBR_PACKAGE_POSTINST KEEN_PBR_RESCUE_TRANSACTION KEEN_PBR_PERSISTENT_TRANSACTION KEEN_PBR_PACKAGE_UNKNOWN_RECOVERY; do' \
  '  if env | grep -q "^$flag="; then echo "installer flag leaked into daemon: $flag" >&2; exit 1; fi' \
  'done' > "$work/opt/etc/init.d/rc.func"

for flag in KEEN_PBR_PACKAGE_POSTINST KEEN_PBR_RESCUE_TRANSACTION KEEN_PBR_PERSISTENT_TRANSACTION KEEN_PBR_PACKAGE_UNKNOWN_RECOVERY; do
    export "$flag=1"
done
sh "$work/S79" start

sed -n '/^FASTNAT_DISPATCH_ACTION=/,/^\. \/opt\/etc\/init.d\/rc.func/p' \
    "$files/opt/etc/init.d/S80keen-pbr" |
    sed "s#/opt/#$work/opt/#g" > "$work/S80-launch"
(
    guard_meta_udp443_start_ownership() { return 0; }
    exit_failed_start() { exit "$1"; }
    set -- start
    . "$work/S80-launch"
)
echo 'S79/S80 startup environment: PASS'

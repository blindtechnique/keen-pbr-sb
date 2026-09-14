# Direct upgrade from v3.0.7-sb.11

The source branch is `main`; Beta is the release label, not a Git branch.
A bridge IPK is not required by the current
configuration migration or installer layout. This describes the implemented
delivery path, not a completed upgrade on a real stable11 router.

## One update from the old panel

1. Stable11 checks GitHub `releases/latest`. Its version parser only recognizes
   `v<version>-sb.<uint32 counter>`, so stable release tags retain this format.
   The corrected Release 12 candidate is `v3.3.1-sb.12`; package/UI versions remain timestamps.
2. The old updater downloads `install.sh` from the selected tag and invokes it
   with `--update`. With no explicit handoff tag, this installer uses its embedded
   `STABLE_RELEASE_TAG`, avoiding a second selection of a different Latest.
   Modern signed updaters continue passing their exact verified tag explicitly.
3. If OpenSSL is missing, the installer installs only `openssl-util` and its
   dependencies from the configured Entware feed before downloading/checking
   the keen-pbr IPK. A failure here stops before keen-pbr installation. It does
   not upgrade nfqws or sing-box or rewrite user configuration.
4. The installer verifies the stable manifest and target IPK, prepares the
   existing rescue helpers and performs the package update. Legacy installations
   without those helpers use the already implemented bootstrap path.
5. The new daemon migrates the versionless configuration through schema v1 to
   v2. `config.json` and `transports.json` remain package conffiles. The update
   path does not run the initial DNS/authentication/component setup wizard.

The initial installer/public-key delivery still relies on the old updater's
GitHub HTTPS trust model. A bridge release would have the same first-delivery
limitation. Package signatures are not skipped; later updates also authenticate
the installer using the key already installed on the router.

## Subsequent releases

Keep compatible stable tags while supporting users who still run stable11;
publishing one temporary bridge as Latest would miss users updating later.
`version.mk` supplies the version and stable release counter. The standalone
installer contains the matching literal; CI checks it against the frozen source.
Advance both for a new stable release and never repoint a published tag.

Updated panels discover the actual build version from full Keenetic IPK asset
names, so a newer timestamp under `v3.3.0-sb.13` is not mistaken for a downgrade
from a timestamp build under `v3.3.0-sb.12`. Release/changelog links still use the
real tag. Discovery metadata does not replace installation signature checks.

## Publication and remaining acceptance

- A push to `main` builds all three Keenetic profiles, uploads a signed
  stable-channel candidate and creates the matching Beta Pre-release. It does
  not change Latest. The manifest channel is already `stable`, so the same
  files/signatures can be promoted later without rebuilding or re-signing.
- Before promotion, build the IPKs and test a real upgrade from stable11 both
  with and without a preinstalled OpenSSL executable. Check preserved routing,
  VPN/group/subscription configuration, API login, service startup and next-update
  detection. Keep the old IPK and exported settings for recovery. On a separately
  authorized test router running stable11, the tagged installer can be invoked
  with `--update` before Latest promotion; its exact-tag download also works for
  a Pre-release. Normal old-panel discovery intentionally remains on the previous
  stable release until promotion.
- Promote the accepted release by removing its Pre-release flag and marking it
  Latest. Keep the same tag, commit and all uploaded files; do not rerun a build
  to perform promotion. Release publishers never overwrite existing assets.
  Stable11 discovers it on its next update check, because it uses `releases/latest`.
- Do not change production routers merely to obtain upgrade acceptance evidence.

Focused offline coverage exercises legacy tag discovery, installer pinning,
dependency preparation/failure, signed-update verification, configuration
migrations and workflow candidate/publication separation. These checks are not
a claim that a real router has already completed this transition.

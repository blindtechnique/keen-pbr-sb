"""What install.sh and the daemon must agree on about sing-box.

Both fetch the same release for the same router, and neither can read the
other: install.sh is downloaded and run standalone on a device where the source
tree does not exist. So every fact they share is stated twice, and the only
thing that can keep the copies honest is a check that fails.

This is the shape the repository already uses where a build-time coupling is
impossible - check-openapi-parity.py for routes, test_test_target_coverage.py
for targets. Both facts here had already drifted or were about to: the daemon
reported the pinned version under the name `tested_version` while the installer
had been renamed to `pinned` (different promises about one number), and the
architecture table was about to be written a third time for the WebUI install.
"""

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
VERSION_MK = REPO_ROOT / "version.mk"
INSTALLER = REPO_ROOT / "install.sh"
VERSION_TEMPLATE = REPO_ROOT / "include" / "keen-pbr" / "version.hpp.in"
POLICY = REPO_ROOT / "src" / "update" / "sing_box_install_policy.cpp"


def pinned_in_version_mk():
    match = re.search(
        r"^SING_BOX_PINNED_VERSION=([0-9]+(?:\.[0-9]+)+)$",
        VERSION_MK.read_text(encoding="utf-8"),
        re.M,
    )
    if match is None:
        raise AssertionError(
            "version.mk does not declare SING_BOX_PINNED_VERSION"
        )
    return match.group(1)


def pinned_in_installer():
    match = re.search(
        r'^SING_BOX_PINNED_VERSION="([0-9]+(?:\.[0-9]+)+)"$',
        INSTALLER.read_text(encoding="utf-8"),
        re.M,
    )
    if match is None:
        raise AssertionError(
            "install.sh does not declare SING_BOX_PINNED_VERSION"
        )
    return match.group(1)


def installer_asset_architectures():
    """Entware family -> official sing-box asset name, as install.sh maps it.

    The installer does it in two hops: the Entware architecture reported by
    opkg is matched to its own KEEN_ARCH, and KEEN_ARCH is matched to the asset
    name. Composing them here gives the one mapping the daemon has to agree
    with.
    """
    text = INSTALLER.read_text(encoding="utf-8")
    family_to_keen = dict(
        re.findall(
            r'^\s*([a-z0-9_]+)-\*\)\s*KEEN_ARCH="([a-z0-9_]+)"', text, re.M
        )
    )
    keen_to_asset = dict(
        re.findall(
            r'^\s*([a-z0-9_]+)\)\s*sing_arch="([a-z0-9_]+)"', text, re.M
        )
    )
    if not family_to_keen or not keen_to_asset:
        raise AssertionError(
            "install.sh no longer states its architecture tables in the "
            "shape this gate reads; the tables are still coupled, so update "
            "the gate deliberately rather than letting it pass vacuously"
        )
    return {
        family: keen_to_asset[keen]
        for family, keen in family_to_keen.items()
        if keen in keen_to_asset
    }


def daemon_asset_architectures():
    text = POLICY.read_text(encoding="utf-8")
    mapping = dict(
        re.findall(
            r'if \(family == "([a-z0-9_]+)"\) return "([a-z0-9_]+)";', text
        )
    )
    if not mapping:
        raise AssertionError(
            "sing_box_install_policy.cpp no longer states its architecture "
            "table in the shape this gate reads"
        )
    return mapping


class TestPinnedVersions(unittest.TestCase):
    def test_installer_matches_version_mk(self):
        self.assertEqual(
            pinned_in_installer(),
            pinned_in_version_mk(),
            "install.sh and version.mk pin different sing-box releases. "
            "version.mk is the source; update install.sh to match.",
        )

    def test_daemon_reads_the_pin_from_version_mk(self):
        # Not a value comparison - a coupling check. If the template stops
        # substituting the variable, the daemon's constant silently becomes
        # whatever was last written by hand, and this gate would then be
        # comparing install.sh against a number nothing produces.
        template = VERSION_TEMPLATE.read_text(encoding="utf-8")
        self.assertIn(
            "@SING_BOX_PINNED_VERSION@",
            template,
            "version.hpp.in no longer substitutes SING_BOX_PINNED_VERSION, so "
            "the daemon's pinned version is no longer derived from version.mk",
        )

    def test_the_pin_is_a_release_and_not_a_range(self):
        # "pinned" has to mean one release. A prefix or a range would make the
        # installer's own equality check against it meaningless.
        pinned = pinned_in_version_mk()
        self.assertRegex(pinned, r"^[0-9]+\.[0-9]+\.[0-9]+$")


class TestArchitectureTables(unittest.TestCase):
    def test_daemon_and_installer_map_the_same_architectures(self):
        # Divergence here does not fail loudly. It fetches the wrong asset:
        # an ARM archive onto a MIPS router, which installs, does not run, and
        # reports as a sing-box problem.
        self.assertEqual(
            daemon_asset_architectures(),
            installer_asset_architectures(),
            "install.sh and sing_box_install_policy.cpp disagree about which "
            "sing-box asset an Entware architecture needs",
        )

    def test_the_tables_are_not_empty(self):
        # Both extractors raise on an unreadable shape, but an empty-but-valid
        # table would make the comparison above pass by matching nothing.
        self.assertGreaterEqual(len(daemon_asset_architectures()), 5)


if __name__ == "__main__":
    unittest.main()

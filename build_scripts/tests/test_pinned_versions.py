"""The pinned sing-box release is stated once and repeated under a gate.

version.mk is the source. CMake reads it into the generated version header, so
the daemon cannot drift by construction. install.sh cannot: it is fetched and
run standalone on a router where version.mk does not exist, so its copy is a
literal and the only thing that can keep it honest is a check that fails.

This is the shape the repository already uses where a build-time coupling is
impossible - check-openapi-parity.py for routes, test_test_target_coverage.py
for targets. A contract stated twice with nothing watching it is a contract
that has already drifted; this one had, before it was even noticed: the daemon
reported the same number under the name `tested_version` while the installer
had been renamed to `pinned`, which are different promises.
"""

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
VERSION_MK = REPO_ROOT / "version.mk"
INSTALLER = REPO_ROOT / "install.sh"
VERSION_TEMPLATE = REPO_ROOT / "include" / "keen-pbr" / "version.hpp.in"


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


if __name__ == "__main__":
    unittest.main()

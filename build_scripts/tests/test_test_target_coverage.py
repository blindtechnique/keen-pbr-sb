"""Every test executable must be built and run by `make test`.

A target missing from NARROW_TEST_TARGETS is not merely unrun: `make test`
stops compiling it, so it can rot unlinkable while the gate stays green.
keen-pbr-native-tunnel-import-tests did exactly that - it lost
config_writer.cpp from its source list and nothing noticed for days, taking
the whole WAL store suite dark with it, because those tests build into no
other target.

The only permitted exception is keen-pbr-firewall-it, which needs Docker and
network namespaces and has its own `make firewall-it`.
"""

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CMAKE = REPO_ROOT / "tests" / "CMakeLists.txt"
MAKEFILE = REPO_ROOT / "Makefile"

# Built explicitly by the `test` recipe rather than through the list.
DIRECTLY_BUILT = {"keen-pbr-tests", "crash-diagnostics-smoke"}
# Needs Docker and netns; covered by `make firewall-it`.
EXEMPT = {"keen-pbr-firewall-it"}


def declared_targets():
    text = CMAKE.read_text(encoding="utf-8")
    return set(re.findall(r"^add_executable\(([A-Za-z0-9_-]+)", text, re.M))


def gated_targets():
    text = MAKEFILE.read_text(encoding="utf-8")
    match = re.search(
        r"^NARROW_TEST_TARGETS\s*:=(.*?)(?=^\S)", text, re.M | re.S
    )
    if match is None:
        raise AssertionError("NARROW_TEST_TARGETS not found in Makefile")
    body = match.group(1).replace("\\", " ")
    return {token for token in body.split() if token}


class TestTargetCoverage(unittest.TestCase):
    def test_every_declared_target_is_gated(self):
        declared = declared_targets()
        self.assertIn(
            "keen-pbr-native-tunnel-import-tests",
            declared,
            "the target this test was written for vanished; update the test "
            "deliberately rather than letting it pass vacuously",
        )
        covered = gated_targets() | DIRECTLY_BUILT | EXEMPT
        missing = sorted(declared - covered)
        self.assertEqual(
            missing,
            [],
            "test executables declared in tests/CMakeLists.txt but neither "
            "built nor run by `make test`: {}. Add them to "
            "NARROW_TEST_TARGETS, or exempt them here with a reason.".format(
                missing
            ),
        )

    def test_gate_lists_no_target_that_does_not_exist(self):
        # A stale name in the list is a silent no-op: make would fail loudly,
        # but a typo'd name that happens to match nothing is worse than a
        # missing one because the list *looks* complete.
        stale = sorted(gated_targets() - declared_targets())
        self.assertEqual(stale, [], "NARROW_TEST_TARGETS names non-targets")

    def test_exemptions_are_real_targets(self):
        # An exemption for a target that no longer exists silently widens the
        # allowed gap for whatever is added under that name next.
        unreal = sorted(EXEMPT - declared_targets())
        self.assertEqual(unreal, [], "exempted names are not declared targets")


if __name__ == "__main__":
    unittest.main()

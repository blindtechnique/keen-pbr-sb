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
# Declared inside `if(KEEN_PBR_FUZZ)`, which is OFF by default and requires
# Clang. Named here rather than left invisible: the anchored pattern this gate
# used to carry could not see an indented declaration at all, so these five
# were exempt by accident. An accidental exemption covers whatever is added
# under the same indentation next.
OPT_IN_ONLY = {
    "keen-pbr-fuzz-srs",
    "keen-pbr-fuzz-config",
    "keen-pbr-fuzz-list",
    "keen-pbr-fuzz-iptables",
    "keen-pbr-fuzz-conntrack",
}
# Compiled into a target through a variable rather than a literal path, or
# deliberately not compiled at all. Every other tests/test_*.cpp must appear in
# some target's source list.
UNCOMPILED_SOURCES: set = set()


def declared_targets():
    text = CMAKE.read_text(encoding="utf-8")
    # Leading whitespace allowed: a declaration inside a conditional is still a
    # declaration, and the gate that cannot see it cannot judge it.
    return set(
        re.findall(r"^[ \t]*add_executable\(([A-Za-z0-9_-]+)", text, re.M)
    )


def compiled_sources():
    """Every tests/*.cpp named in tests/CMakeLists.txt, by bare file name."""
    text = CMAKE.read_text(encoding="utf-8")
    return {
        Path(match).name
        for match in re.findall(r"[\w./-]+\.cpp", text)
        if not match.startswith("../")
    }


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
        covered = gated_targets() | DIRECTLY_BUILT | EXEMPT | OPT_IN_ONLY
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
        unreal = sorted((EXEMPT | OPT_IN_ONLY) - declared_targets())
        self.assertEqual(unreal, [], "exempted names are not declared targets")

    def test_every_test_source_belongs_to_a_target(self):
        # The other half of the failure this gate was written for. A target
        # missing from the list rots unlinkable; a SOURCE missing from every
        # target never compiles at all, and no target-level check can see it -
        # the file simply is not mentioned anywhere. That is how
        # test_ndms_native_import_wal_store.cpp went dark: it built into one
        # target and no other, so when that target stopped building, so did it.
        present = compiled_sources()
        orphans = sorted(
            path.name
            for path in (REPO_ROOT / "tests").glob("test_*.cpp")
            if path.name not in present and path.name not in UNCOMPILED_SOURCES
        )
        self.assertEqual(
            orphans,
            [],
            "test sources in tests/ that no target compiles: {}. Add them to "
            "a target's source list, or record them in UNCOMPILED_SOURCES "
            "with a reason.".format(orphans),
        )


if __name__ == "__main__":
    unittest.main()

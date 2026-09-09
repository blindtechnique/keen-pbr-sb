"""Compile the actual route-proof source without post-3.4 UAPI enum names.

The native runner has newer headers than MIPS Entware. Poisoning the late
identifiers after reading those headers reproduces the missing-name failure
without downloading a toolchain or pretending to validate the target ABI.
"""

from pathlib import Path
import shutil
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
CXX = shutil.which("g++")
SOURCE = "src/api/trusted_local_connection.cpp"
LATE_ATTRIBUTES = (
    "RTA_MFC_STATS", "RTA_VIA", "RTA_NEWDST", "RTA_PREF",
    "RTA_ENCAP_TYPE", "RTA_ENCAP",
)
WIRE_VALUES = """
static_assert(keen_pbr3::kRouteAttributeVia == 18U);
static_assert(keen_pbr3::kRouteAttributeNewDestination == 19U);
static_assert(keen_pbr3::kRouteAttributeEncapsulationType == 21U);
static_assert(keen_pbr3::kRouteAttributeEncapsulation == 22U);
"""


@unittest.skipUnless(sys.platform.startswith("linux") and CXX,
                     "Linux GCC headers are required")
class NetlinkUapiCompatibilityTest(unittest.TestCase):
    def compile(self, prefix: str = "", suffix: str = ""):
        unit = ('#include <linux/rtnetlink.h>\n' + prefix +
                f'#include "{SOURCE}"\n' + WIRE_VALUES + suffix)
        return subprocess.run(
            [CXX, "-std=c++17", "-DWITH_API", "-I", str(ROOT),
             "-fsyntax-only", "-x", "c++", "-"],
            input=unit, text=True, capture_output=True, timeout=30,
        )

    def test_wire_values_match_modern_header(self):
        result = self.compile(suffix="""
static_assert(keen_pbr3::kRouteAttributeVia == RTA_VIA);
static_assert(keen_pbr3::kRouteAttributeNewDestination == RTA_NEWDST);
static_assert(keen_pbr3::kRouteAttributeEncapsulationType == RTA_ENCAP_TYPE);
static_assert(keen_pbr3::kRouteAttributeEncapsulation == RTA_ENCAP);
""")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_source_does_not_require_post_linux_3_4_enum_names(self):
        result = self.compile("#pragma GCC poison " + " ".join(LATE_ATTRIBUTES) + "\n")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_fixture_rejects_the_original_missing_enum_dependency(self):
        result = self.compile(
            "#pragma GCC poison " + " ".join(LATE_ATTRIBUTES) + "\n",
            "constexpr auto old_dependency = RTA_MFC_STATS + 1;\n",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("poisoned", result.stderr)
        self.assertIn("RTA_MFC_STATS", result.stderr)


if __name__ == "__main__":
    unittest.main()

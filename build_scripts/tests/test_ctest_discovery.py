import copy
import importlib.util
from pathlib import Path
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "check-ctest-discovery.py"
SPEC = importlib.util.spec_from_file_location("ctest_discovery", SCRIPT)
discovery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(discovery)


class CTestDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.source = Path("/source")
        self.build = Path("/build")
        self.native = ["keen-pbr-tests", "crash-diagnostics-smoke", "focused-tests"]
        self.document = {"tests": []}
        for name in self.native:
            self.add(name, "native", [str(self.build / "tests" / name)])
        for name, fixture in discovery.LIFECYCLE_FIXTURES.items():
            self.add(name, "package-lifecycle",
                     ["/bin/sh", str(self.source / "tests/package_it" / fixture), str(self.source)])
        self.add("dns", "package-dns", ["/bin/sh", "/source/tests/dns.sh"])

    def add(self, name, label, command):
        self.document["tests"].append({"name": name, "command": command, "properties": [
            {"name": "LABELS", "value": [label]},
            {"name": "RUN_SERIAL", "value": True},
            {"name": "TIMEOUT", "value": 180},
            {"name": "WORKING_DIRECTORY", "value": str(self.source)},
        ]})

    def validate(self):
        discovery.validate_discovery(self.document, self.native, self.source, self.build)

    def test_valid_discovery(self):
        self.validate()

    def test_empty_discovery_cannot_pass(self):
        self.document["tests"] = []
        with self.assertRaisesRegex(ValueError, "no tests"):
            self.validate()

    def test_every_native_and_lifecycle_fixture_is_required(self):
        original = copy.deepcopy(self.document)
        for index in range(len(self.native) + len(discovery.LIFECYCLE_FIXTURES)):
            with self.subTest(index=index):
                self.document = copy.deepcopy(original)
                self.document["tests"].pop(index)
                with self.assertRaises(ValueError):
                    self.validate()

    def test_disabled_unlabelled_parallel_or_unbounded_tests_fail(self):
        original = copy.deepcopy(self.document)
        for name, value in (("DISABLED", True), ("LABELS", []), ("RUN_SERIAL", False),
                            ("TIMEOUT", 0), ("WORKING_DIRECTORY", "/wrong"), ("SKIP_RETURN_CODE", 0)):
            with self.subTest(property=name):
                self.document = copy.deepcopy(original)
                properties = self.document["tests"][0]["properties"]
                properties[:] = [p for p in properties if p["name"] != name]
                properties.append({"name": name, "value": value})
                with self.assertRaises(ValueError):
                    self.validate()

    def test_only_container_ownership_fixture_can_skip_on_nonroot_host(self):
        root_test = next(t for t in self.document["tests"] if t["name"] == "keen-pbr-netfilter-hook-signals")
        root_test["properties"].append({"name": "SKIP_RETURN_CODE", "value": 77})
        self.validate()
        root_test["properties"][-1]["value"] = 1
        with self.assertRaisesRegex(ValueError, "skip condition"):
            self.validate()

    def test_duplicate_and_manual_aggregate_fail(self):
        self.document["tests"].append(copy.deepcopy(self.document["tests"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.validate()
        self.document["tests"].pop()
        self.add("manual", "native", [str(self.build / "tests/manual")])
        with self.assertRaisesRegex(ValueError, "unexpected"):
            self.validate()

    def test_missing_wrong_and_noop_commands_fail(self):
        for index in (0, len(self.native)):
            original = self.document["tests"][index]["command"]
            for command in ([], ["/bin/true"], original + ["--list-tests"]):
                with self.subTest(index=index, command=command):
                    # Extra native arguments could list tests instead of running
                    # them. Lifecycle fixtures legitimately have path arguments.
                    if index == len(self.native) and len(command) > len(original):
                        continue
                    self.document["tests"][index]["command"] = command
                    with self.assertRaises(ValueError):
                        self.validate()
            self.document["tests"][index]["command"] = original


if __name__ == "__main__":
    unittest.main()

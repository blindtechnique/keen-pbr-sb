"""Check fuzz selection/budgets/failure propagation without running Go or services."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "build_scripts" / "fuzz-transport-manager.sh"
TARGETS = ["FuzzShareLink", "FuzzBase64Payload", "FuzzTransportConfig", "FuzzTransportInput"]
FAKE_GO = '''#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
with open(os.environ["FUZZ_RUNNER_RECORD"], "a", encoding="utf-8") as output:
    output.write(json.dumps(args) + "\\n")
if "-list" in args:
    name = args[args.index("-list") + 1].strip("^$")
    if name != os.environ.get("FUZZ_RUNNER_MISSING"):
        print(name)
if "-fuzz" in args:
    name = args[args.index("-fuzz") + 1].strip("^$")
    if name == os.environ.get("FUZZ_RUNNER_FAIL"):
        sys.exit(23)
'''


@unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "Linux/Bash development runner")
class GoFuzzRunnerTests(unittest.TestCase):
    def run_runner(self, **overrides):
        with tempfile.TemporaryDirectory(prefix="kpbr-fuzz-runner-") as directory:
            temp = Path(directory)
            executable = temp / "go"
            executable.write_text(FAKE_GO, encoding="utf-8")
            executable.chmod(0o700)
            record = temp / "calls.jsonl"
            env = {key: value for key, value in os.environ.items() if not key.startswith("GO_FUZZ_")}
            env.update({"PATH": str(temp) + os.pathsep + env["PATH"],
                        "GOCACHE": str(temp / "cache"), "FUZZ_RUNNER_RECORD": str(record)})
            env.update(overrides)
            result = subprocess.run(["bash", str(RUNNER)], env=env, text=True,
                                    capture_output=True, timeout=10, check=False)
            calls = [json.loads(line) for line in record.read_text().splitlines()] if record.exists() else []
            return result, calls

    def test_all_targets_have_explicit_budgets(self):
        result, calls = self.run_runner()
        self.assertEqual(result.returncode, 0, result.stderr)
        mutations = [args for args in calls if "-fuzz" in args]
        self.assertEqual(len(calls), 8)
        self.assertEqual([args[args.index("-fuzz") + 1] for args in mutations],
                         [f"^{name}$" for name in TARGETS])
        for args in mutations:
            for flag, expected in {"-run": "^$", "-fuzztime": "30s", "-parallel": "2",
                                   "-timeout": "3m", "-fuzzminimizetime": "5s"}.items():
                self.assertEqual(args[args.index(flag) + 1], expected)

    def test_single_api_target_and_iteration_budget(self):
        result, calls = self.run_runner(GO_FUZZ_TARGET="FuzzTransportInput", GO_FUZZ_TIME="100x")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[-1][1], "./internal/api")
        self.assertIn("100x", calls[-1])

    def test_failure_stops_later_targets(self):
        result, calls = self.run_runner(FUZZ_RUNNER_FAIL="FuzzBase64Payload")
        self.assertEqual(result.returncode, 23)
        self.assertEqual(len([args for args in calls if "-fuzz" in args]), 2)

    def test_missing_target_cannot_succeed(self):
        result, calls = self.run_runner(FUZZ_RUNNER_MISSING="FuzzShareLink")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(len(calls), 1)

    def test_invalid_or_unbounded_budgets_fail_before_go(self):
        for settings in [{"GO_FUZZ_TIME": "0"}, {"GO_FUZZ_TIME": "0s"},
                         {"GO_FUZZ_TIMEOUT": "0"}, {"GO_FUZZ_PARALLEL": "0"},
                         {"GO_FUZZ_TARGET": "FuzzMissing"}]:
            with self.subTest(settings=settings):
                result, calls = self.run_runner(**settings)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()

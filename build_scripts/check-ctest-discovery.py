#!/usr/bin/env python3
"""Check configured CTest discovery, not just add_test text in a CMake file."""

import argparse
import json
from pathlib import Path
import subprocess
import sys


LIFECYCLE_FIXTURES = {
    "keen-pbr-netfilter-hook-signals": "run-netfilter-hook-signals.sh",
    "keen-pbr-service-start-environment": "run-service-start-environment.sh",
    "keen-pbr-keenetic-iptables-wait": "run-keenetic-iptables-wait.sh",
    "keen-pbr-keenetic-startup-dependencies": "run-keenetic-startup-dependencies.sh",
    "keen-pbr-keenetic-meta-udp443-cleanup": "run-keenetic-meta-udp443-cleanup.sh",
}


def validate_discovery(document, expected_native, source_root, build_root):
    tests = document.get("tests", [])
    if not tests:
        raise ValueError("CTest discovered no tests; check root enable_testing()")
    names = [test["name"] for test in tests]
    if len(names) != len(set(names)):
        raise ValueError("CTest has duplicate test names")
    native, lifecycle = set(), set()
    for test in tests:
        name = test["name"]
        properties = {item["name"]: item["value"] for item in test.get("properties", [])}
        labels = properties.get("LABELS", [])
        if labels not in (["native"], ["package-dns"], ["package-lifecycle"]):
            raise ValueError(f"{name}: missing or unexpected test label: {labels}")
        if properties.get("DISABLED"):
            raise ValueError(f"{name}: registered but disabled")
        if "SKIP_RETURN_CODE" in properties and (
                name != "keen-pbr-netfilter-hook-signals" or properties["SKIP_RETURN_CODE"] != 77):
            raise ValueError(f"{name}: unexpected skip condition")
        if not properties.get("RUN_SERIAL") or not 0 < properties.get("TIMEOUT", 0) <= 1800:
            raise ValueError(f"{name}: tests need serial execution and a finite timeout")
        if Path(properties.get("WORKING_DIRECTORY", "")) != source_root:
            raise ValueError(f"{name}: wrong working directory")
        command = test.get("command", [])
        if not command:
            raise ValueError(f"{name}: executable missing; build the test target first")
        if labels == ["native"]:
            native.add(name)
            if command != [str(build_root / "tests" / name)]:
                raise ValueError(f"{name}: CTest does not run the expected test executable")
        elif labels == ["package-lifecycle"]:
            lifecycle.add(name)
            script = LIFECYCLE_FIXTURES.get(name)
            if (script is None or len(command) < 3 or command[0] != "/bin/sh"
                    or command[1] != str(source_root / "tests/package_it" / script)):
                raise ValueError(f"{name}: CTest does not run the expected lifecycle fixture")
    if native != set(expected_native):
        raise ValueError(f"CTest/native differs from make test: missing={sorted(set(expected_native) - native)}, "
                         f"unexpected={sorted(native - set(expected_native))}")
    if lifecycle != set(LIFECYCLE_FIXTURES):
        raise ValueError(f"CTest lifecycle fixtures missing: {sorted(set(LIFECYCLE_FIXTURES) - lifecycle)}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("native_targets", nargs="+")
    args = parser.parse_args()
    build_root = args.build_dir.resolve()
    source_root = Path(__file__).resolve().parent.parent
    try:
        result = subprocess.run(
            ["ctest", "--test-dir", str(build_root), "--show-only=json-v1"],
            check=True, capture_output=True, text=True, timeout=60,
        )
        document = json.loads(result.stdout)
        validate_discovery(document, args.native_targets, source_root, build_root)
        for target in args.native_targets:
            if not (build_root / "tests" / target).is_file():
                raise ValueError(f"test binary not built: {target}")
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        print(f"CTest discovery failed: {error}", file=sys.stderr)
        return 1
    print(f"CTest discovery verified: {len(args.native_targets)} native suites, "
          f"{len(LIFECYCLE_FIXTURES)} lifecycle fixtures")
    return 0


if __name__ == "__main__":
    sys.exit(main())

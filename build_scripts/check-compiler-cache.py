#!/usr/bin/env python3
"""Verify cached C++ objects can locate source fixtures before a full build."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "build_scripts/tests/fixtures/compiler-cache/source_paths.cpp"


def run(command: list[str], *, cwd: Path, env: dict[str, str]) -> str:
    result = subprocess.run(command, cwd=cwd, env=env, text=True,
                            capture_output=True, timeout=60)
    if result.returncode:
        raise RuntimeError(f"{command[0]} failed ({result.returncode}):\n"
                           f"{result.stdout}{result.stderr}")
    return result.stdout


def check(compiler: str) -> None:
    cache_parent = ROOT / ".cache"
    cache_parent.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="compiler-cache-probe-", dir=cache_parent) as temporary:
        work = Path(temporary)
        build = work / "build/tests"
        build.mkdir(parents=True)
        config = work / "ccache.conf"
        config.write_text("", encoding="utf-8")
        env = dict(os.environ)
        env.update(CCACHE_DIR=str(work / "cache"), CCACHE_CONFIGPATH=str(config))
        obj = build / "probe.o"
        exe = build / "probe"
        for attempt in ("cold", "cache-hit"):
            run(["ccache", compiler, "-std=c++17", "-c", str(PROBE), "-o", str(obj)],
                cwd=build, env=env)
            run([compiler, str(obj), "-o", str(exe)], cwd=build, env=env)
            # Compilation and CTest/manual invocation use different directories.
            for cwd in (ROOT, work):
                run([str(exe)], cwd=cwd, env=env)
            print(f"{compiler}: fixture paths verified ({attempt})", flush=True)
            obj.unlink()
            exe.unlink()
        stats = dict(line.split() for line in
                     run(["ccache", "--print-stats"], cwd=work, env=env).splitlines())
        hits = int(stats.get("direct_cache_hit", 0)) + int(stats.get("preprocessed_cache_hit", 0))
        if hits < 1 or int(stats.get("cache_miss", 0)) < 1:
            raise RuntimeError(f"Expected both a fresh compilation and a real compiler cache hit: {stats}")
        print(f"{compiler}: confirmed cold miss and cache hit", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", required=True)
    check(parser.parse_args().compiler)

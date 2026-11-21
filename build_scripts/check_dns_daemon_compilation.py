"""Compile only changed DNS integration translation units, without linking/IPK."""
import concurrent.futures
import json
from pathlib import Path
import shlex
import subprocess
import sys


def main():
    database = json.loads((Path(sys.argv[1]) / "compile_commands.json").read_text())
    wanted = {
        "src/daemon/daemon_core.cpp", "src/daemon/daemon_runtime.cpp",
        "src/daemon/daemon_resolver.cpp", "src/config/config.cpp",
        "src/config/dependency_analysis.cpp", "src/dns/dnsmasq_gen.cpp",
    }
    if "--intercept" in sys.argv[2:]:
        wanted = {
            "src/daemon/daemon_core.cpp", "src/firewall/firewall_runtime.cpp",
            "src/firewall/iptables.cpp", "src/firewall/nftables.cpp",
        }
    if "--intercept-health" in sys.argv[2:]:
        wanted = {
            "src/daemon/daemon_api.cpp", "src/daemon/daemon_core.cpp",
            "src/firewall/firewall_runtime.cpp", "src/api/health_response.cpp",
        }
    if "--intercept-cleanup" in sys.argv[2:]:
        wanted = {
            "src/daemon/daemon_core.cpp", "src/daemon/daemon_runtime.cpp",
            "src/daemon/daemon_intercept.cpp", "src/firewall/firewall_runtime.cpp",
        }
    commands = []
    for entry in database:
        command = entry.get("arguments") or shlex.split(entry["command"])
        source = next((name for name in wanted if entry["file"].endswith("/" + name)), None)
        if source is None or not any("CMakeFiles/keen-pbr.dir/" in arg for arg in command):
            continue
        args, skip = [], False
        for arg in command:
            if skip:
                skip = False
            elif arg in ("-o", "-MF", "-MT", "-MQ"):
                skip = True
            elif arg not in ("-c", "-MD", "-MMD"):
                args.append(arg)
        commands.append((source, args + ["-fsyntax-only", "-O0"], entry["directory"]))
    if {c[0] for c in commands} != wanted or len(commands) != len(wanted):
        raise RuntimeError("Incomplete main-daemon compilation database")

    def check(item):
        source, args, cwd = item
        result = subprocess.run(args, cwd=cwd, capture_output=True, text=True)
        print(f"{source}: {'PASS' if result.returncode == 0 else 'FAIL'}", flush=True)
        if result.stdout or result.stderr:
            print(result.stdout + result.stderr, flush=True)
        return result.returncode

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        return int(any(list(pool.map(check, commands))))


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""SET-01 lab, not a production firewall writer or a router benchmark.

Run ONLY in a disposable Docker container with --network none and NET_ADMIN.
The handwritten classifier mirrors the small MARK/save/RETURN shape in
IptablesFirewall::build_rule_lines; it does not exercise daemon publication.
JSON lines are emitted to stdout. No downloaded data or external traffic.
"""

import argparse
import json
import os
import platform
import re
import shlex
import socket
import statistics
import subprocess
import time
from pathlib import Path


MASK = "0xffff0000"
MARK = "0x40000"
PORT = 42042
CHAINS = ("S01_ROOT", "S01_CLASS")


def command(*args, data=None, required=True):
    result = subprocess.run(args, input=data, text=True, capture_output=True, timeout=30)
    if required and result.returncode:
        raise RuntimeError(f"{shlex.join(args)}: {result.stderr.strip()}")
    return result


def emit(kind, **fields):
    print(json.dumps({"kind": kind, **fields}, ensure_ascii=False), flush=True)


def classifier_lines(sets, selector="", sticky=False, allow_conntrack=True):
    """Combine only the destination OR within ONE logical rule and family."""
    lines = []
    for name in sets:
        match = f"-A S01_CLASS -m set --match-set {name} dst -p udp --dport {PORT}"
        if selector:
            match += " " + selector
        lines.append(f"{match} -j MARK --set-xmark {MARK}/{MASK}")
        if allow_conntrack:
            lines.append(f"{match} -j CONNMARK --save-mark --nfmask {MASK} --ctmask {MASK}")
        lines.append(f"{match} -j RETURN")
    root = []
    if sticky:
        if not allow_conntrack:
            raise ValueError("conntrack restore/save is tested only in mangle")
        root.extend((
            f"-A S01_ROOT -j CONNMARK --restore-mark --nfmask {MASK} --ctmask {MASK}",
            f"-A S01_ROOT -m mark ! --mark 0/{MASK} -j RETURN",
        ))
    root.extend((
        "-A S01_ROOT -j S01_CLASS",
        "-A S01_ROOT -m mark --mark 0x40042/0xffffffff -m comment --comment hit -j RETURN",
        "-A S01_ROOT -m mark --mark 0x42/0xffffffff -m comment --comment miss -j RETURN",
        "-A S01_ROOT -m comment --comment unexpected -j RETURN",
    ))
    return root, lines


class Lab:
    def __init__(self, backend, family, table):
        self.family = family
        self.table = table
        self.af = socket.AF_INET if family == 4 else socket.AF_INET6
        stem = "iptables" if family == 4 else "ip6tables"
        self.tool = stem + ("-legacy" if backend == "legacy" else "-nft")
        self.restore = self.tool + "-restore"
        self.save = self.tool + "-save"
        self.parent = f"s01_u{family}"
        self.candidate = f"s01_c{family}"
        self.dynamic = f"s01_d{family}"
        self.leaves = [f"s01_{family}_{index:02}" for index in range(64)]
        self.sockets = []

    def address(self, index):
        return f"198.18.1.{index + 1}" if self.family == 4 else f"2001:db8:1::{index + 1:x}"

    def set_members(self, members, parent=None):
        name = parent or self.parent
        lines = [f"flush {name}", *(f"add {name} {member}" for member in members)]
        command("ipset", "restore", data="\n".join(lines) + "\n")

    def setup(self):
        command(self.tool, "-t", self.table, "-N", "S01_ROOT")
        command(self.tool, "-t", self.table, "-N", "S01_CLASS")
        command(self.tool, "-t", self.table, "-A", "OUTPUT", "-p", "udp", "-m", "multiport",
                "--dports", f"{PORT},{PORT + 1}", "-j", "S01_ROOT")
        prefix = "198.18.1.0/24" if self.family == 4 else "2001:db8:1::/64"
        command("ip", f"-{self.family}", "route", "add", "local", prefix, "dev", "lo")
        family_name = "inet" if self.family == 4 else "inet6"
        lines = []
        for index, name in enumerate(self.leaves):
            lines += [f"create {name} hash:net family {family_name}", f"add {name} {self.address(index)}"]
        lines += [f"create {self.parent} list:set size 64", f"create {self.candidate} list:set size 64",
                  f"create {self.dynamic} hash:net family {family_name} timeout 1"]
        command("ipset", "restore", data="\n".join(lines) + "\n")
        self.rx = {}
        for port in (PORT, PORT + 1):
            sock = socket.socket(self.af, socket.SOCK_DGRAM)
            if self.family == 6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
            sock.settimeout(1)
            sock.bind(("0.0.0.0" if self.family == 4 else "::", port))
            self.rx[port] = sock
            self.sockets.append(sock)
        self.tx = self.sender()

    def sender(self):
        sock = socket.socket(self.af, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, 0x42)
        sock.bind(("127.0.0.1" if self.family == 4 else "::1", 0))
        self.sockets.append(sock)
        return sock

    def apply(self, members, selector="", exceptions=(), sticky=False, terminal=None):
        root, lines = classifier_lines(members, selector, sticky, self.table == "mangle")
        lines = list(exceptions) + lines
        if terminal:
            # Keep an earlier pass/drop rule outside the grouped rule.
            lines.insert(0, f"-A S01_CLASS -d {self.address(1)} -j {terminal}")
        text = "\n".join(("*" + self.table, "-F S01_ROOT", "-F S01_CLASS", *root, *lines, "COMMIT", ""))
        started = time.perf_counter_ns()
        command(self.restore, "--noflush", data=text)
        return (time.perf_counter_ns() - started) / 1e6, len(lines)

    def snapshot(self):
        text = command(self.save, "-c", "-t", self.table).stdout
        audit = dict(hit=0, miss=0, unexpected=0, classifier=0, dropped=0)
        for line in text.splitlines():
            count = re.match(r"^\[(\d+):(\d+)\] (-A S01_(?:ROOT|CLASS) .*)$", line)
            if not count:
                continue
            packets = int(count[1])
            tokens = shlex.split(count[3])
            if "--comment" in tokens:
                key = tokens[tokens.index("--comment") + 1]
                if key in audit:
                    audit[key] += packets
            if tokens[1] == "S01_CLASS" and "--set-xmark" in tokens:
                audit["classifier"] += packets
            if tokens[-2:] == ["-j", "DROP"]:
                audit["dropped"] += packets
        return audit

    def send(self, index, count=1, port=PORT, sender=None):
        tx = sender or self.tx
        payload = b"set01-offline" * 4
        started = time.perf_counter_ns()
        for offset in range(0, count, 32):
            size = min(32, count - offset)
            for _ in range(size):
                tx.sendto(payload, (self.address(index), port))
            for _ in range(size):
                received = self.rx[port].recv(2048)
                assert received == payload, "local UDP receiver mismatch"
        return (time.perf_counter_ns() - started) / count

    def expect_packet(self, index, hit, port=PORT):
        before = self.snapshot()
        self.send(index, port=port)
        after = self.snapshot()
        assert after["unexpected"] == before["unexpected"], "foreign mark bits changed"
        assert after["hit"] - before["hit"] == int(hit), (before, after, hit)
        assert after["miss"] - before["miss"] == int(not hit), (before, after, hit)

    def semantics(self):
        passed = []
        for mode in ("flat", "union"):
            self.set_members(self.leaves[:4])
            selected = self.leaves[:4] if mode == "flat" else [self.parent]
            self.apply(selected)
            self.expect_packet(0, True)
            self.expect_packet(3, True)
            self.expect_packet(63, False)
            self.expect_packet(0, False, port=PORT + 1)
            command("ipset", "add", self.leaves[3], self.address(0))
            before = self.snapshot()["classifier"]
            self.expect_packet(0, True)
            assert self.snapshot()["classifier"] - before == 1
            command("ipset", "del", self.leaves[3], self.address(0))
            self.apply(selected, selector="! -s " + ("127.0.0.1" if self.family == 4 else "::1"))
            self.expect_packet(0, False)
            self.apply(selected, terminal="RETURN")
            self.expect_packet(1, False)
            self.expect_packet(2, True)
            self.apply(selected, terminal="DROP")
            try:
                self.tx.sendto(b"blocked-in-lab", (self.address(1), PORT))
            except PermissionError:
                pass  # OUTPUT DROP may report EPERM to the sender.
            self.rx[PORT].settimeout(0.1)
            try:
                self.rx[PORT].recv(2048)
                raise AssertionError("earlier DROP was bypassed")
            except socket.timeout:
                pass
            finally:
                self.rx[PORT].settimeout(1)
            assert self.snapshot()["dropped"] == 1
            assert self.snapshot()["classifier"] == 0
            coverage = "first/last/miss/port/overlap/source/pass/drop/foreign-mark"
            if self.table == "mangle":
                self.apply(selected, sticky=True)
                fresh = self.sender()
                self.send(0, 32, sender=fresh)
                assert self.snapshot()["classifier"] == 1, "conntrack fast path not preserved"
                coverage += "/conntrack"
            passed.append(f"{mode}: {coverage}")
        self.apply([self.parent])
        assert command("ipset", "destroy", self.leaves[0], required=False).returncode != 0
        assert command("ipset", "add", self.parent, self.candidate, required=False).returncode != 0
        assert command("ipset", "swap", self.parent, self.leaves[0], required=False).returncode != 0
        self.expect_packet(0, True)
        # ipset restore is not atomic: a failed candidate retains its prefix.
        failed = command("ipset", "restore", data=f"add {self.candidate} {self.leaves[63]}\nadd {self.candidate} s01_missing\n", required=False)
        assert failed.returncode != 0
        command("ipset", "test", self.candidate, self.leaves[63])
        self.expect_packet(0, True)
        command("ipset", "swap", self.parent, self.candidate)
        self.expect_packet(0, False)
        self.expect_packet(63, True)
        command("ipset", "swap", self.parent, self.candidate)
        self.expect_packet(0, True)
        self.expect_packet(63, False)
        passed.append("references/nesting/schema-rejection/partial-restore/swap/rollback")
        self.set_members([self.leaves[0], self.dynamic])
        command("ipset", "add", self.dynamic, self.address(62), "timeout", "1")
        self.expect_packet(62, True)
        time.sleep(1.2)
        self.expect_packet(62, False)
        self.expect_packet(0, True)
        passed.append("dynamic-child-TTL-without-parent-rebuild")
        emit("semantics", family=self.family, table=self.table, cases=passed, passed=True)

    def benchmark(self, packets, rounds):
        for count in (1, 4, 16, 64):
            self.set_members(self.leaves[:count])
            for label, index in (("first", 0), ("last", count - 1), ("miss", 63 if count < 64 else 64)):
                samples = {"flat": [], "union": []}
                apply_ms = {"flat": [], "union": []}
                for repeat in range(rounds):
                    # Interleave order so the second implementation is not always warmer.
                    order = ("flat", "union") if repeat % 2 == 0 else ("union", "flat")
                    for mode in order:
                        members = self.leaves[:count] if mode == "flat" else [self.parent]
                        elapsed, _ = self.apply(members)
                        apply_ms[mode].append(elapsed)
                        self.send(index, 128)
                        before = self.snapshot()
                        samples[mode].append(self.send(index, packets))
                        after = self.snapshot()
                        field = "miss" if label == "miss" else "hit"
                        assert after[field] - before[field] == packets
                        assert after["unexpected"] == before["unexpected"]
                medians = {mode: statistics.median(values) for mode, values in samples.items()}
                rows_per_set = 3 if self.table == "mangle" else 2
                emit("benchmark", family=self.family, table=self.table, members=count, position=label,
                     packets_per_round=packets, rounds=rounds, classifier_rows={"flat": rows_per_set * count, "union": rows_per_set},
                     ns_per_local_udp_roundtrip=medians, samples=samples,
                     union_vs_flat=medians["union"] / medians["flat"],
                     median_restore_ms={mode: statistics.median(values) for mode, values in apply_ms.items()},
                     note="Cold classifier forced for every packet; includes Python/send/receive overhead. Not VPN throughput or Keenetic acceptance.")

    def cleanup(self):
        for sock in self.sockets:
            sock.close()
        command(self.tool, "-t", self.table, "-D", "OUTPUT", "-p", "udp", "-m", "multiport",
                "--dports", f"{PORT},{PORT + 1}", "-j", "S01_ROOT", required=False)
        for chain in CHAINS:
            command(self.tool, "-t", self.table, "-F", chain, required=False)
        for chain in CHAINS:
            command(self.tool, "-t", self.table, "-X", chain, required=False)
        # Parents MUST release references before child destruction.
        for name in (self.parent, self.candidate, self.dynamic, *self.leaves):
            command("ipset", "destroy", name, required=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute-in-disposable-container", action="store_true")
    parser.add_argument("--backend", choices=("legacy", "nft-compat"), default="legacy")
    parser.add_argument("--table", choices=("raw", "mangle"), default="raw")
    parser.add_argument("--packets", type=int, default=8192)
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--semantics-only", action="store_true")
    parser.add_argument("--families", type=int, choices=(4, 6), nargs="+", default=[4, 6])
    args = parser.parse_args()
    if not args.execute_in_disposable_container:
        parser.error("explicit disposable-container execution flag required")
    if not Path("/.dockerenv").exists() or os.geteuid() != 0:
        parser.error("run inside a disposable root Docker container, never on a router")
    links = json.loads(command("ip", "-j", "link", "show").stdout)
    if {link["ifname"] for link in links} != {"lo"}:
        parser.error("isolated --network none required: only lo may exist")
    if not 32 <= args.packets <= 65536 or not 1 <= args.rounds <= 9:
        parser.error("use 32..65536 packets and 1..9 rounds")
    command("ip", "link", "set", "lo", "up")
    emit("environment", kernel=platform.release(), architecture=platform.machine(), backend=args.backend, table=args.table, families=args.families,
         ipset=command("ipset", "--version").stdout.strip(), python=platform.python_version(),
         iptables=command("iptables-legacy" if args.backend == "legacy" else "iptables-nft", "--version").stdout.strip())
    for family in args.families:
        lab = Lab(args.backend, family, args.table)
        try:
            lab.setup()
            lab.semantics()
            if not args.semantics_only:
                lab.benchmark(args.packets, args.rounds)
        finally:
            lab.cleanup()
    emit("complete", passed=True)


if __name__ == "__main__":
    main()

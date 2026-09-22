"""Finite LAN probes and offline summaries for LOAD-01; standard library only.

Does not authenticate, mutate configuration, switch a VPN, flush DNS, or fetch
remote media. Raw traces are local artifacts, not automatically published.
"""
import argparse
import concurrent.futures
import http.client
import ipaddress
import json
import math
from pathlib import Path
import secrets
import socket
import statistics
import struct
import subprocess
import time


def bounded_int(low, high):
    def parse(value):
        number = int(value)
        if not low <= number <= high:
            raise argparse.ArgumentTypeError(f"expected {low}..{high}")
        return number
    return parse


def percentiles(values):
    if not values:
        return None
    ordered = sorted(values)
    return {"n": len(ordered), "min": ordered[0], "median": statistics.median(ordered),
            "p95": ordered[math.ceil(len(ordered) * .95) - 1], "max": ordered[-1]}


def dns_packet(name, identifier):
    labels = name.rstrip(".").encode("ascii").split(b".")
    if not labels or any(not 1 <= len(label) <= 63 for label in labels):
        raise ValueError("invalid DNS labels")
    question = b"".join(bytes([len(label)]) + label for label in labels) + b"\0\0\1\0\1"
    if len(question) > 259:
        raise ValueError("DNS name too long")
    return struct.pack("!6H", identifier, 0x100, 1, 0, 0, 0) + question


def check_dns_reply(response, query):
    if len(response) < 12:
        raise ValueError("short DNS reply")
    identifier, flags, questions, answers, _, _ = struct.unpack("!6H", response[:12])
    if identifier != struct.unpack("!H", query[:2])[0] or not flags & 0x8000:
        raise ValueError("unmatched DNS reply")
    if flags & 0x200 or flags & 15 or questions != 1 or not answers:
        raise ValueError("truncated/error/empty DNS answer")
    # These probes send an uncompressed question; validate the echoed question.
    if response[12:len(query)].lower() != query[12:].lower():
        raise ValueError("DNS question mismatch")
    offset, addresses = len(query), 0
    for _ in range(answers):
        # Walk only the encoded owner name, never follow untrusted pointers.
        while True:
            if offset >= len(response):
                raise ValueError("truncated DNS owner")
            length = response[offset]
            offset += 1
            if length == 0:
                break
            if length & 0xC0 == 0xC0:
                if offset >= len(response):
                    raise ValueError("truncated DNS pointer")
                pointer = ((length & 0x3F) << 8) | response[offset]
                if pointer >= offset - 1:
                    raise ValueError("forward DNS pointer")
                offset += 1
                break
            if length > 63 or offset + length > len(response):
                raise ValueError("invalid DNS owner label")
            offset += length
        if offset + 10 > len(response):
            raise ValueError("truncated DNS record")
        kind, cls, _, size = struct.unpack("!HHIH", response[offset:offset + 10])
        offset += 10
        if offset + size > len(response):
            raise ValueError("truncated DNS data")
        addresses += int(kind == 1 and cls == 1 and size == 4)
        offset += size
    if not addresses:
        raise ValueError("no IPv4 answers")
    return addresses


def probe_dns(router, domain, timeout):
    query = dns_packet(domain, secrets.randbelow(65536))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(timeout)
        client.connect((router, 53))  # Replies from this resolver only.
        client.send(query)
        response = client.recv(4096)
    return check_dns_reply(response, query)


def probe_http(router, timeout):
    # Plain LAN HTTP: do not construct urllib's HTTPS handler/Windows trust store
    # inside the timing window, and never inherit an environment HTTP proxy.
    connection = http.client.HTTPConnection(router, 12121, timeout=timeout)
    try:
        connection.request("GET", "/api/auth/status", headers={"Connection": "close"})
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError(f"HTTP {response.status}")
        payload = response.read(8193)
        if len(payload) > 8192 or not isinstance(json.loads(payload), dict):
            raise ValueError("invalid auth-status response")
    finally:
        connection.close()
    return 200


def measure_probe(kind, router, domain, timeout, round_number, lane):
    start = time.monotonic()
    row = {"kind": kind, "round": round_number, "lane": lane, "unix": time.time()}
    try:
        row["result"] = probe_http(router, timeout) if kind == "panel" else probe_dns(router, domain, timeout)
        row["ok"] = True
    except (OSError, ValueError, http.client.HTTPException) as error:
        row.update(ok=False, error=type(error).__name__ + ": " + str(error)[:200])
    row["ms"] = (time.monotonic() - start) * 1000
    return row


def run_probes(args):
    ipaddress.IPv4Address(args.router)
    dns_packet(args.domain, 1)
    # Exclusively create; never overwrite an earlier run.
    with args.output.open("x", encoding="utf-8") as output:
        output.write(json.dumps({"meta": {"format": "keenetic-probes-v2", "router": args.router,
            "http_client": "direct HTTPConnection, fresh TCP, no proxy/TLS setup",
            "concurrency": args.concurrency, "rounds": args.rounds, "interval": args.interval,
            "timeout": args.timeout, "dns_name": args.domain, "dns_cache": "not flushed"}}) + "\n")
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            for round_number in range(args.rounds):
                start = time.monotonic()
                # DNS and HTTP are separate bursts; maximum concurrency is N, not 2N.
                for kind in ("panel", "dns"):
                    futures = [pool.submit(measure_probe, kind, args.router, args.domain,
                        args.timeout, round_number, lane) for lane in range(args.concurrency)]
                    for future in concurrent.futures.as_completed(futures):
                        output.write(json.dumps(future.result()) + "\n")
                    output.flush()
                if round_number + 1 < args.rounds:
                    time.sleep(max(0, args.interval - (time.monotonic() - start)))
        output.write(json.dumps({"complete": args.rounds}) + "\n")
    summary = summarize_probes(args.output)
    print(json.dumps(summary, indent=2))
    return summary


def capture(args):
    ipaddress.IPv4Address(args.router)
    if args.rounds > 120:
        raise ValueError("too many rounds")
    script = Path(__file__).with_name("keenetic-load-snapshot.sh").read_bytes().replace(b"\r\n", b"\n")
    samples = args.rounds + 3
    trace = args.output.with_suffix(".tsv")
    errors = args.output.with_suffix(".ssh.log")
    command = ["ssh", "-T", "-p", str(args.ssh_port), "-i", str(args.key),
               "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
               "-o", "ConnectTimeout=8", "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=2",
               "root@" + args.router, f"/opt/usr/bin/sh -s -- {samples} {args.interval}"]
    with trace.open("xb") as output, errors.open("xb") as error_output:
        with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=output, stderr=error_output) as child:
            try:
                child.stdin.write(script)
                child.stdin.close()
                time.sleep(2)
                if child.poll() is not None:
                    raise RuntimeError("observer exited early; inspect SSH log")
                probes = run_probes(args)
                if child.wait(timeout=samples * args.interval + 30) != 0:
                    raise RuntimeError("observer failed; inspect SSH log")
            finally:
                if child.poll() is None:
                    child.terminate()  # Only this SSH client; remote script is finite too.
                    try:
                        child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait()
    summary = summarize_snapshot(trace)
    with args.output.with_suffix(".summary.json").open("x", encoding="utf-8") as output:
        json.dump({"snapshot": summary, "probes": probes}, output, indent=2)
    if not summary["complete"] or not probes["complete"]:
        raise SystemExit("incomplete capture")
    if any(probes[kind]["errors"] for kind in ("panel", "dns")):
        raise SystemExit("capture complete with probe failures; do not increase load automatically")
    print("CAPTURE COMPLETE: " + str(trace))


def summarize_probes(path):
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
    result = {"meta": rows[0]["meta"], "complete": "complete" in rows[-1]}
    for kind in ("panel", "dns"):
        selected = [row for row in rows if row.get("kind") == kind]
        expected = result["meta"]["rounds"] * result["meta"]["concurrency"]
        result["complete"] = result["complete"] and len(selected) == expected and len({
            (row["round"], row["lane"]) for row in selected}) == expected
        result[kind] = {"requests": len(selected), "errors": sum(not row["ok"] for row in selected),
                        "ms_success": percentiles([row["ms"] for row in selected if row["ok"]])}
    return result


def summarize_snapshot(path):
    meta, samples, completed = {}, {}, False
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        fields = line.split("\t")
        if fields[0] == "meta":
            meta[fields[1]] = fields[2]
        elif fields[0] == "complete":
            completed = True
        elif fields[0] == "sample":
            samples[fields[2]] = {"t": float(fields[2]), "proc": {}, "queue": {}, "mem": {}, "net": {}}
        elif fields[0] in ("cpu", "mem", "proc", "queue", "net", "temp", "end_sample"):
            sample = samples[fields[1]]
            if fields[0] == "cpu":
                sample["cpu"] = list(map(int, fields[2:]))
            elif fields[0] == "mem":
                sample["mem"][fields[2]] = int(fields[3])
            elif fields[0] == "proc":
                sample["proc"][(fields[2], fields[4])] = (fields[3], int(fields[5]) + int(fields[6]), int(fields[7]))
            elif fields[0] == "queue":
                sample["queue"][fields[2]] = tuple(map(int, fields[3:]))
            elif fields[0] == "net":
                sample["net"][fields[2]] = tuple(map(int, fields[3:]))
            elif fields[0] == "temp":
                sample.setdefault("temp_c", []).append(int(fields[3]) / 1000)
            elif fields[0] == "end_sample":
                sample["complete"] = True
    ordered = list(samples.values())
    cpus = int(meta["cpus"])
    result = {"meta": meta, "complete": completed and len(ordered) == int(meta["samples"])
              and all(row.get("complete") for row in ordered), "samples": len(ordered),
              "duration_s": ordered[-1]["t"] - ordered[0]["t"], "processes": {}, "queues": {},
              "interfaces": {}, "cpu_busy_pct_total_capacity": [], "process_set_changes": 0,
              "initial_processes_still_present": set(ordered[0]["proc"]) <= set(ordered[-1]["proc"]),
              "process_churn": {}}
    for row in ordered:
        groups = {}
        for family, _, rss_kib in row["proc"].values():
            if rss_kib < 0:
                raise ValueError("process disappeared before RSS snapshot; repeat the sample")
            groups[family] = groups.get(family, 0) + rss_kib / 1024
        for family, rss_mib in groups.items():
            group = result["processes"].setdefault(family, {"sum_rss_mib": [], "cpu_pct_one_core": []})
            group["sum_rss_mib"].append(rss_mib)
    for before, after in zip(ordered, ordered[1:]):
        ticks = [end - start for start, end in zip(before["cpu"], after["cpu"])]
        total = sum(ticks)
        if total <= 0 or any(tick < 0 for tick in ticks):
            raise ValueError("CPU counters reset or nonpositive interval")
        result["cpu_busy_pct_total_capacity"].append(100 * (total - ticks[3] - ticks[4]) / total)
        changed = set(before["proc"]) ^ set(after["proc"])
        result["process_set_changes"] += len(changed)
        for identity in changed:
            family = (before["proc"].get(identity) or after["proc"][identity])[0]
            result["process_churn"][family] = result["process_churn"].get(family, 0) + 1
        grouped_ticks = {}
        for identity, (family, end, _) in after["proc"].items():
            if identity in before["proc"]:
                delta = end - before["proc"][identity][1]
                if delta < 0:
                    raise ValueError("process CPU counter decreased")
                grouped_ticks[family] = grouped_ticks.get(family, 0) + delta
        for family, delta in grouped_ticks.items():
            result["processes"][family]["cpu_pct_one_core"].append(100 * cpus * delta / total)
    result["cpu_busy_pct_total_capacity"] = percentiles(result["cpu_busy_pct_total_capacity"])
    for group in result["processes"].values():
        for key, values in group.items():
            group[key] = percentiles(values)
    for key in ("MemAvailable", "SwapFree"):
        result[key + "_mib"] = percentiles([row["mem"][key] / 1024 for row in ordered if key in row["mem"]])
    result["max_sensor_temp_c"] = max((v for row in ordered for v in row.get("temp_c", [])), default=None)
    for queue in set().union(*(row["queue"] for row in ordered)):
        values = [row["queue"].get(queue) for row in ordered]
        owners = {v[0] for v in values if v}
        stable = len(owners) == 1 and all(v is not None for v in values)
        if stable:
            stable = all(end[2] >= start[2] and end[3] >= start[3]
                         for start, end in zip(values, values[1:]))
        item = {"stable_owner_and_presence": stable, "max_queued": max(v[1] for v in values if v)}
        if stable:
            # sequence is uint32; avoid treating owner recreation as wraparound.
            item.update(kernel_drops_delta=values[-1][2] - values[0][2],
                userspace_drops_delta=values[-1][3] - values[0][3],
                sequence_delta=(values[-1][4] - values[0][4]) % (2**32))
        result["queues"][queue] = item
    for interface, first in ordered[0]["net"].items():
        last = ordered[-1]["net"].get(interface)
        if last is not None and all(b >= a for a, b in zip(first, last)):
            result["interfaces"][interface] = dict(zip(("rx_bytes", "rx_packets", "tx_bytes", "tx_packets"),
                                                       [b - a for a, b in zip(first, last)]))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("probe", "capture"):
        probes = commands.add_parser(name)
        probes.add_argument("--router", required=True, help="explicit IPv4 of the test router")
        probes.add_argument("--output", required=True, type=Path)
        probes.add_argument("--domain", default="example.com")
        probes.add_argument("--concurrency", choices=(1, 5, 10), type=int, default=1)
        probes.add_argument("--rounds", type=bounded_int(1, 120), default=12)
        probes.add_argument("--interval", type=bounded_int(1, 60), default=5)
        probes.add_argument("--timeout", type=bounded_int(1, 5), default=2)
        if name == "capture":
            probes.add_argument("--key", required=True, type=Path)
            probes.add_argument("--ssh-port", type=bounded_int(1, 65535), default=22)
    for name in ("summarize-snapshot", "summarize-probes"):
        commands.add_parser(name).add_argument("path", type=Path)
    args = parser.parse_args()
    if args.command == "probe":
        result = run_probes(args)
        if any(result[kind]["errors"] for kind in ("panel", "dns")):
            raise SystemExit(1)
    elif args.command == "capture":
        capture(args)
    else:
        summary = summarize_snapshot(args.path) if args.command == "summarize-snapshot" else summarize_probes(args.path)
        print(json.dumps(summary, indent=2))
        if not summary["complete"]:
            raise SystemExit(1)


if __name__ == "__main__":
    main()

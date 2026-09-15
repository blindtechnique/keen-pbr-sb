"""Pure fixtures: no router connection, no DNS lookup, no live load."""
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("keenetic_load", ROOT / "build_scripts/diagnostics/keenetic-load.py")
LOAD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LOAD)


def snapshot(second_identity="100\tcore\t123", queue="2\t0\t0\t0\t104", finish=True):
    result = "meta\tformat\tkeenetic-load-v1\nmeta\tcpus\t2\nmeta\tprocess_memory_unit\tVmRSS_KiB\nmeta\tsamples\t2\n"
    for t, cpu, identity, ticks, seq in [
            (10, "100\t0\t100\t800\t0\t0\t0\t0", "100\tcore\t123", 20, "2\t0\t0\t0\t100"),
            (11, "130\t0\t110\t960\t0\t0\t0\t0", second_identity, 40, queue)]:
        result += f"sample\t0\t{t}\ncpu\t{t}\t{cpu}\n"
        result += f"mem\t{t}\tMemAvailable\t409600\nmem\t{t}\tSwapFree\t1048576\n"
        result += f"proc\t{t}\t{identity}\t{ticks}\t0\t4096\nqueue\t{t}\t300\t{seq}\n"
        result += f"net\t{t}\tbr0\t{t*100}\t{t}\t{t*50}\t{t}\nend_sample\t{t}\n"
    return result + ("complete\t2\n" if finish else "")


class KeeneticLoadTests(unittest.TestCase):
    def summarize(self, body):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.tsv"
            path.write_text(body, encoding="utf-8")
            return LOAD.summarize_snapshot(path)

    def test_cpu_denominators_memory_and_queue(self):
        result = self.summarize(snapshot())
        self.assertTrue(result["complete"])
        self.assertEqual(result["cpu_busy_pct_total_capacity"]["max"], 20)
        self.assertEqual(result["processes"]["core"]["cpu_pct_one_core"]["max"], 20)
        self.assertEqual(result["processes"]["core"]["sum_rss_mib"]["max"], 4)
        self.assertEqual(result["queues"]["300"]["sequence_delta"], 4)
        self.assertEqual(result["interfaces"]["br0"]["rx_bytes"], 100)

    def test_pid_reuse_is_not_cpu_sample(self):
        result = self.summarize(snapshot(second_identity="100\tcore\t456"))
        self.assertEqual(result["process_set_changes"], 2)
        self.assertFalse(result["initial_processes_still_present"])
        self.assertIsNone(result["processes"]["core"]["cpu_pct_one_core"])

    def test_incomplete_is_not_pass(self):
        self.assertFalse(self.summarize(snapshot(finish=False))["complete"])
        self.assertFalse(self.summarize(snapshot().replace("end_sample\t11\n", ""))["complete"])

    def test_queue_recreated_not_treated_as_counter_wrap(self):
        result = self.summarize(snapshot(queue="3\t0\t0\t0\t2"))
        self.assertFalse(result["queues"]["300"]["stable_owner_and_presence"])
        self.assertNotIn("sequence_delta", result["queues"]["300"])

    def test_queue_sequence_wrap_with_same_owner(self):
        result = self.summarize(snapshot(queue="2\t0\t1\t2\t5").replace("0\t0\t100\n", "0\t0\t4294967290\n"))
        self.assertEqual(result["queues"]["300"]["sequence_delta"], 11)
        self.assertEqual(result["queues"]["300"]["kernel_drops_delta"], 1)
        self.assertEqual(result["queues"]["300"]["userspace_drops_delta"], 2)

    def test_dns_actual_answer_and_rejections(self):
        query = LOAD.dns_packet("example.com", 42)
        reply = struct.pack("!6H", 42, 0x8180, 1, 1, 0, 0) + query[12:] + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\xc0\x00\x02\x01"
        self.assertEqual(LOAD.check_dns_reply(reply, query), 1)
        for broken in (reply[:10], reply[:-1], b"\0\0" + reply[2:],
                       reply[:2] + b"\x83\x80" + reply[4:], reply[:12],
                       reply.replace(b"example", b"invalid")):
            with self.subTest(size=len(broken)), self.assertRaises(ValueError):
                LOAD.check_dns_reply(broken, query)

    def test_probe_completion_requires_all_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "probes.jsonl"
            rows = [{"meta": {"rounds": 1, "concurrency": 1}}, {"complete": 1}]
            path.write_text("\n".join(map(json.dumps, rows)))
            self.assertFalse(LOAD.summarize_probes(path)["complete"])

    def test_percentiles_nearest_rank(self):
        self.assertIsNone(LOAD.percentiles([]))
        self.assertEqual(LOAD.percentiles(list(range(1, 21)))["p95"], 19)

    def test_http_direct_small_json_and_no_redirect(self):
        with mock.patch.object(LOAD.http.client, "HTTPConnection") as factory:
            response = factory.return_value.getresponse.return_value
            response.status = 200
            response.read.return_value = b'{"enabled":true}'
            self.assertEqual(LOAD.probe_http("192.0.2.1", 2), 200)
            factory.assert_called_once_with("192.0.2.1", 12121, timeout=2)
            factory.return_value.request.assert_called_once_with("GET", "/api/auth/status", headers={"Connection": "close"})
            for status, body in [(302, b"{}"), (200, b"[]"), (200, b"x" * 8193)]:
                response.status, response.read.return_value = status, body
                with self.assertRaises(ValueError):
                    LOAD.probe_http("192.0.2.1", 2)
            self.assertEqual(factory.return_value.close.call_count, 4)


if __name__ == "__main__":
    unittest.main()

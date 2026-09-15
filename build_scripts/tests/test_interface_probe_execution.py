"""Check Daemon wiring in addition to the network-free C++ saturation tests."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class InterfaceProbeExecution(unittest.TestCase):
    def test_regular_round_has_a_reserved_bounded_worker(self):
        header = (ROOT / "src/daemon/daemon.hpp").read_text(encoding="utf-8")
        self.assertRegex(
            header, r"BlockingExecutor\s+interface_probe_executor_\s*\{\s*1\s*,\s*1\s*\}",
        )
        runtime = (ROOT / "src/daemon/daemon_runtime.cpp").read_text(encoding="utf-8")
        self.assertRegex(runtime, r'interface_probe_executor_\.try_post\(\s*"interface-probe"')
        self.assertNotRegex(runtime, r'blocking_executor_\.try_post\(\s*"interface-probe"')

    def test_manual_work_cannot_fill_the_reserved_round_queue(self):
        runtime = (ROOT / "src/daemon/daemon_runtime.cpp").read_text(encoding="utf-8")
        self.assertRegex(runtime, r'blocking_executor_\.try_post\(\s*"targeted-interface-probe:"')
        self.assertNotRegex(runtime, r'interface_probe_executor_\.try_post\(\s*"targeted-')

    def test_every_bulk_teardown_also_retires_the_reserved_worker(self):
        core = (ROOT / "src/daemon/daemon_core.cpp").read_text(encoding="utf-8")
        for method in ("cancel_pending", "cancel_pending_and_shutdown"):
            # Destructor fallback, failed startup rollback, normal shutdown.
            bulk = list(re.finditer(r"\bblocking_executor_\." + method + r"\(\)", core))
            reserved = list(re.finditer(r"\binterface_probe_executor_\." + method + r"\(\)", core))
            self.assertEqual(len(bulk), 3)
            self.assertEqual(len(reserved), len(bulk))
            for site in bulk:
                self.assertTrue(
                    any(0 < site.start() - other.start() < 300 for other in reserved),
                    f"reserved worker not retired before bulk {method} at {site.start()}",
                )


if __name__ == "__main__":
    unittest.main()

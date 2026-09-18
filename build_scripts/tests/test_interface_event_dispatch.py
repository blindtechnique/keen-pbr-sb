"""Keep the live daemon wiring aligned with the C++ event-flood regressions."""

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class InterfaceEventDispatch(unittest.TestCase):
    def test_unchanged_link_returns_before_expensive_side_effects(self):
        source = (ROOT / "src/daemon/daemon_core.cpp").read_text(encoding="utf-8")
        handler = source.split("void Daemon::handle_interface_event(", 1)[1]
        handler = handler.split("\nvoid Daemon::", 1)[0]
        guard = handler.index("if (!interface_event_requires_runtime_observation(event))")
        self.assertRegex(handler[guard:], r"\Aif \([^\n]+\) \{\s*return;\s*\}")
        for effect in (
            "teardown_conntrack_events();",
            "status_stream_->reconcile();",
            'request_remote_access_reconcile_from_control("interface event")',
        ):
            self.assertLess(guard, handler.index(effect), effect)
        # Neighbour metadata and main-table route fencing keep their distinct paths.
        self.assertLess(handler.index("if (event.neighbor_changed) return;"), guard)
        self.assertLess(handler.index("if (event.route_changed)"), guard)

    def test_live_netlink_adapter_uses_the_tested_bounded_drain(self):
        source = (ROOT / "src/routing/interface_monitor.cpp").read_text(encoding="utf-8")
        handler = source.split("void InterfaceMonitor::handle_events()", 1)[1]
        handler = handler.split("\nvoid InterfaceMonitor::", 1)[0]
        self.assertIn("drain_pending_batches([this]()", handler)
        self.assertNotIn("while (true)", handler)
        self.assertIn("nl_recvmsgs_default(impl_->socket)", handler)
        self.assertIn("impl_->callback(Event{", handler)


if __name__ == "__main__":
    unittest.main()

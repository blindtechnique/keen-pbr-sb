"""Focused execution of S80's restart branch with lifecycle operations stubbed."""

import pathlib
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "packages/keenetic/keen-pbr/files/opt/etc/init.d/S80keen-pbr"


class ServiceProcessRestartTest(unittest.TestCase):
    def setUp(self):
        self.source = SCRIPT.read_text(encoding="utf-8")
        begin = self.source.index("    restart|restartall)\n")
        end = self.source.index("    stop)\n", begin)
        self.branch = self.source[begin:end]

    def run_branch(self, *, stack=True, stop_status=0, manager_status=0):
        stubs = f"""
lifecycle_lock_or_fail() {{ echo lock; }}
stop_service_for_action() {{ echo stop:$1:$2; return {stop_status}; }}
restart_stack_transport_manager() {{ echo manager:restart; return {manager_status}; }}
log_error() {{ echo error; }}
run_recovery_guard() {{ echo recovery:$1; }}
begin_start_control_lease() {{ echo start-lease; }}
establish_fastnat_start_rollback_authority() {{ echo fastnat:$1; }}
prepare_start() {{ echo prepare-start; }}
reapply_dnsmasq_config() {{ echo resolver; }}
exit_failed_start() {{ exit "$1"; }}
RESTART_TRANSPORT_MANAGER={'yes' if stack else 'no'}
set -- restart ''
case "$1" in
{self.branch}
esac
echo dispatch:$1
exit "${{RESTART_STACK_MANAGER_STATUS:-0}}"
"""
        return subprocess.run(["sh", "-c", stubs], text=True, capture_output=True, check=False)

    def test_full_stack_restarts_manager_between_daemon_stop_and_start(self):
        result = self.run_branch()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), [
            "lock", "stop:stop:no", "manager:restart", "recovery:restart",
            "start-lease", "fastnat:restart", "prepare-start", "resolver", "dispatch:start",
        ])

    def test_original_daemon_restart_does_not_start_restarting_manager(self):
        result = self.run_branch(stack=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("manager:restart", result.stdout)
        self.assertIn("dispatch:start", result.stdout)

    def test_failed_manager_still_restores_panel_but_reports_failure(self):
        result = self.run_branch(manager_status=7)
        self.assertEqual(result.returncode, 7)
        self.assertIn("manager:restart\nerror\nrecovery:restart", result.stdout)
        self.assertIn("dispatch:start", result.stdout)

    def test_failed_daemon_stop_does_not_restart_manager(self):
        result = self.run_branch(stop_status=1)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("manager:restart", result.stdout)
        self.assertNotIn("dispatch:start", result.stdout)

    def test_launcher_is_detached_delayed_and_has_no_nfqws_command(self):
        begin = self.source.index("    restart-stack-background)\n")
        end = self.source.index("    restart-stack)\n", begin)
        launcher = self.source[begin:end]
        self.assertIn("trap '' HUP", launcher)
        self.assertIn("unset KEEN_PBR_UPDATE_LOCK_PID KEEN_PBR_UPDATE_LOCK_TOKEN", launcher)
        self.assertIn('sleep 1\n            exec "$0" restart-stack', launcher)
        self.assertIn(") </dev/null >/dev/null 2>&1 &", launcher)
        self.assertNotIn("lifecycle_lock_or_fail", launcher)
        self.assertNotRegex(self.source, r"(?m)^\s*/opt/[^\n]*nfqws[^\n]*(?:restart|stop|start)")
        self.assertIn("/opt/etc/init.d/S79transport-manager restart", self.source)


if __name__ == "__main__":
    unittest.main()

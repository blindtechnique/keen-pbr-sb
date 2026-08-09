from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Optional


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "build_scripts" / "check-nfqws-assets.py"


class NfqwsAssetsGateFixture(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.share = (
            self.root
            / "packages/keenetic/keen-pbr/files/opt/usr/share/keen-pbr"
        )
        self.blobs = self.share / "nfqws-blobs"
        self.strategies = self.share / "nfqws-strategies"
        self.build_scripts = self.root / "build_scripts"
        self.blobs.mkdir(parents=True)
        self.strategies.mkdir(parents=True)
        self.build_scripts.mkdir(parents=True)

        blob = self.blobs / "fixture.bin"
        blob.write_bytes(b"fixture\0blob")
        digest = hashlib.sha256(blob.read_bytes()).hexdigest()
        (self.blobs / "SHA256SUMS").write_text(
            f"{digest}  {blob.name}\n", encoding="utf-8"
        )
        (self.share / "nfqws-required-blobs").write_text("", encoding="utf-8")
        self.known = self.build_scripts / "nfqws-assets.known-issues"
        self.known.write_text("", encoding="utf-8")
        self.write_profile()

    @staticmethod
    def rotating_pool(proto: str) -> str:
        return (
            "--lua-desync=circular:fails=2 "
            f"--lua-desync=fake:blob={proto}_one:strategy=1 "
            f"--lua-desync=fake:blob={proto}_two:strategy=2 "
            f"--filter-{'tcp' if proto == 'tcp' else 'udp'}=443"
        )

    def write_profile(
        self,
        *,
        name: str = "default",
        ipv6: Optional[str] = "0",
        tcp: Optional[str] = None,
        quic: Optional[str] = None,
        udp: Optional[str] = None,
        quic_opt_out: str = "",
        comments: tuple[str, ...] = (),
    ) -> None:
        profile = self.strategies / name
        profile.mkdir(parents=True, exist_ok=True)
        lines = [
            "TCP_PORTS=443",
            "UDP_PORTS=443",
            f'NFQWS_ARGS="{tcp if tcp is not None else self.rotating_pool("tcp")}"',
            f'NFQWS_ARGS_QUIC="{quic if quic is not None else self.rotating_pool("quic")}"',
            f'NFQWS_ARGS_UDP="{udp if udp is not None else self.rotating_pool("udp")}"',
            'NFQWS_BASE_ARGS=""',
            'NFQWS_ARGS_IPSET=""',
        ]
        if quic_opt_out:
            lines.append(f"ROTATION_UNAVAILABLE_QUIC={quic_opt_out}")
        if ipv6 is not None:
            lines.append(f"IPV6_ENABLED={ipv6}")
        lines.extend(f"# {comment}" for comment in comments)
        (profile / "nfqws2.conf").write_text(
            "\n".join(lines) + "\n", encoding="utf-8"
        )

    def run_gate(self) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        # A hostile/accidental ambient override must be irrelevant. Fixtures
        # select their tree only through the explicit hidden test argument.
        environment["KEEN_PBR_NFQWS_GATE_ROOT"] = str(self.root / "ignored")
        environment["PYTHONUTF8"] = "1"
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--repo-root", str(self.root)],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=environment,
        )

    @staticmethod
    def waiver_key(output: str, prefix: str) -> str:
        match = re.search(
            rf"waiver key: ({re.escape(prefix)}[^\r\n]+)", output
        )
        if match is None:
            raise AssertionError(f"waiver key {prefix!r} not found in:\n{output}")
        return match.group(1)

    def test_valid_fixture_passes(self) -> None:
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_only_exact_one_disables_rotation_check(self) -> None:
        self.write_profile(quic="", quic_opt_out="yes")
        invalid = self.run_gate()
        self.assertEqual(invalid.returncode, 1)
        self.assertIn("ROTATION_UNAVAILABLE_QUIC", invalid.stdout)
        self.assertIn("0 или 1", invalid.stdout)

        self.write_profile(quic="", quic_opt_out="1")
        valid = self.run_gate()
        self.assertEqual(valid.returncode, 0, valid.stdout + valid.stderr)

    def test_opt_out_cannot_contradict_a_real_pool(self) -> None:
        self.write_profile(quic_opt_out="1")
        result = self.run_gate()
        self.assertEqual(result.returncode, 1)
        self.assertIn("противоречит рабочему пулу", result.stdout)

    def test_waiver_is_bound_to_exact_pool_shape(self) -> None:
        self.write_profile(quic="")
        initial = self.run_gate()
        self.assertEqual(initial.returncode, 1)
        key = self.waiver_key(initial.stdout, "shallow-pool|default|quic|")
        self.known.write_text(
            key + "\n", encoding="utf-8"
        )
        accepted = self.run_gate()
        self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)

        self.write_profile(quic="--lua-desync=fake:strategy=1")
        changed = self.run_gate()
        self.assertEqual(changed.returncode, 1)
        self.assertIn("ids=1", changed.stdout)
        self.assertIn("устаревшая waiver", changed.stdout)

    def test_strategy_numbers_outside_lua_desync_do_not_form_pool(self) -> None:
        self.write_profile(
            quic=(
                "--lua-desync=circular:fails=2 "
                "--other=:strategy=1,:strategy=2"
            )
        )
        result = self.run_gate()
        self.assertEqual(result.returncode, 1)
        self.assertIn("ids=0", result.stdout)

    def test_identical_strategy_bodies_do_not_form_two_choices(self) -> None:
        self.write_profile(
            quic=(
                "--lua-desync=circular:fails=2 "
                "--lua-desync=fake:repeats=1:strategy=1 "
                "--lua-desync=fake:repeats=1:strategy=2"
            )
        )
        result = self.run_gate()
        self.assertEqual(result.returncode, 1)
        self.assertIn("ids=2, distinct_bodies=1", result.stdout)

    def test_new_dialogue_marker_is_not_hidden_by_profile_waiver(self) -> None:
        self.write_profile(comments=("your file",))
        initial = self.run_gate()
        self.assertEqual(initial.returncode, 1)
        key = self.waiver_key(initial.stdout, "dialogue|default|your file|")
        self.known.write_text(
            key + "\n", encoding="utf-8"
        )
        accepted = self.run_gate()
        self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)

        self.write_profile(comments=("your file", "your previous"))
        changed = self.run_gate()
        self.assertEqual(changed.returncode, 1)
        self.assertIn("your previous", changed.stdout)

    def test_missing_ipv6_and_tied_policy_fail_deterministically(self) -> None:
        self.write_profile(ipv6=None)
        missing = self.run_gate()
        self.assertEqual(missing.returncode, 1)
        self.assertIn("явно равен 0 или 1", missing.stdout)

        self.write_profile(ipv6="0")
        self.write_profile(name="second", ipv6="1")
        tied = self.run_gate()
        self.assertEqual(tied.returncode, 1)
        self.assertIn("не имеет единой majority-политики", tied.stdout)

    def test_ipv6_waiver_is_bound_to_value_and_majority(self) -> None:
        self.write_profile(ipv6="1")
        self.write_profile(name="second", ipv6="0")
        self.write_profile(name="third", ipv6="0")
        self.known.write_text(
            "ipv6-exception|default|value=1|baseline=0\n",
            encoding="utf-8",
        )
        accepted = self.run_gate()
        self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)

        self.write_profile(name="third", ipv6="1")
        changed = self.run_gate()
        self.assertEqual(changed.returncode, 1)
        self.assertIn("baseline=1", changed.stdout)
        self.assertIn("устаревшая waiver", changed.stdout)

    def test_unknown_or_stale_waiver_fails(self) -> None:
        self.known.write_text(
            "shallow-pool|removed|quic|present=0|sha256=deadbeef|"
            "circular=0|ids=0|bodies=0\n",
            encoding="utf-8",
        )
        result = self.run_gate()
        self.assertEqual(result.returncode, 1)
        self.assertIn("неизвестная или устаревшая waiver", result.stdout)

    def test_ambient_fixture_override_cannot_replace_production_tree(self) -> None:
        environment = os.environ.copy()
        environment["KEEN_PBR_NFQWS_GATE_ROOT"] = str(self.root)
        environment["PYTHONUTF8"] = "1"
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=environment,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("nfqws assets gate: OK", result.stdout)


if __name__ == "__main__":
    unittest.main()

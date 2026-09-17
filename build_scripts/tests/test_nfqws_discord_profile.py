"""Discord inside Max: boundaries, reproducibility and shipped assets."""
from __future__ import annotations

import hashlib
import re
import runpy
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SHARE = ROOT / "packages/keenetic/keen-pbr/files/opt/usr/share/keen-pbr"
EXPERIMENT = "03 max"
KEYS = ("discord_tcp_exp", "discord_media_tcp_exp", "discord_udp_exp")


class DiscordProfileTest(unittest.TestCase):
    def setUp(self) -> None:
        self.gen = runpy.run_path(str(ROOT / "build_scripts/build-nfqws-strategies.py"))
        self.gate = runpy.run_path(str(ROOT / "build_scripts/check-nfqws-assets.py"))
        self.assertIn(EXPERIMENT, self.gen["PROFILES"])
        self.text, self.required = self.gen["build"](EXPERIMENT, self.gen["PROFILES"][EXPERIMENT])
        self.values = self.gate["parse_shell_assignments"](self.text)
        baseline_spec = dict(self.gen["PROFILES"][EXPERIMENT], discord_experiment=False)
        self.base, self.base_required = self.gen["build"](EXPERIMENT, baseline_spec)
        self.base_values = self.gate["parse_shell_assignments"](self.base)

    def block(self, key: str) -> list[str]:
        text = self.values["NFQWS_ARGS_CUSTOM"]
        return re.search(rf"--new={key}\s+(.*?)(?=--new=|$)", text, re.S)[1].split()

    def test_experiment_stays_in_max_and_other_assignments_are_unchanged(self):
        self.assertEqual(tuple(self.gen["PROFILES"]), ("01 safe", "02 balanced", "03 max"))
        self.assertTrue(self.text.startswith('# keen-pbr-sb · профиль «МАКСИМАЛЬНЫЙ»\n'))
        self.assertIn("Эксперимент", self.text)
        for key, value in self.values.items():
            if key not in ("NFQWS_BASE_ARGS", "NFQWS_ARGS_CUSTOM"):
                self.assertEqual(value.split(), self.base_values[key].split(), key)
        custom = self.values["NFQWS_ARGS_CUSTOM"]
        for key in KEYS:
            custom = re.sub(rf"--new={key}\s+.*?(?=--new=|$)", "", custom, flags=re.S)
        self.assertEqual(custom.split(), self.base_values["NFQWS_ARGS_CUSTOM"].split())
        for profile in ("01 safe", "02 balanced"):
            text, _ = self.gen["build"](profile, self.gen["PROFILES"][profile])
            self.assertNotIn("_exp", text)

    def test_only_declared_ports_domains_and_protocols_enter_experiment(self):
        tcp = self.block("discord_tcp_exp")
        media = self.block("discord_media_tcp_exp")
        udp = self.block("discord_udp_exp")
        self.assertIn("--filter-tcp=443", tcp)
        self.assertIn("--hostlist-domains=discord.com,discord.gg,discordapp.com,discordapp.net,discord.media", tcp)
        self.assertIn("--filter-tcp=2053,2083,2087,2096,8443", media)
        self.assertIn("--hostlist-domains=discord.media", media)
        for block in (tcp, media):
            self.assertIn("--filter-l7=tls", block)
            self.assertIn("--hostlist-exclude=/opt/etc/nfqws2/lists/exclude.list", block)
        self.assertIn("--filter-udp=50000-50099,19294-19344", udp)
        self.assertIn("--filter-l7=discord,stun", udp)
        self.assertFalse(any("--hostlist" in token for token in udp))
        custom = " ".join(self.values["NFQWS_ARGS_CUSTOM"].split())
        self.assertLess(custom.index("--new=discord_udp_exp"), custom.index("--new=discord_udp "))
        self.assertLess(custom.index("--new=discord_udp_exp"), custom.index("--new=webrtc_passthrough"))

    def test_observation_and_actions_have_separate_windows(self):
        for key in KEYS:
            tokens = self.block(key)
            index = next(i for i, token in enumerate(tokens) if token.startswith("--lua-desync=circular:"))
            self.assertIn("--payload=all", tokens[:index])
            self.assertIn("--in-range=x", tokens[index + 1:])
            self.assertIn("--payload=" + ("discord_ip_discovery,stun" if key == KEYS[2] else "tls_client_hello"), tokens[index + 1:])
            detector = tokens[index]
            self.assertIn("fails=2", detector)
            self.assertIn("hostkey=host_ip", detector)
            self.assertNotIn("reset=", detector)
            if key == KEYS[2]:
                self.assertIn("--out-range=-n4", tokens[:index])
                self.assertIn("--in-range=-n2", tokens[:index])
                self.assertIn("--out-range=<n2", tokens[index + 1:])
                self.assertNotIn("retrans=", detector)
                self.assertIn("udp_out=4", detector)
                self.assertIn("udp_in=1", detector)
            else:
                self.assertIn("--in-range=-s9652", tokens[:index])
                self.assertIn("--out-range=-s66996", tokens[:index])
                self.assertIn("retrans=2", detector)
                self.assertIn("inseq=8192", detector)
            material = "\0".join(tokens[:index] + [detector.split(":kpbr_rev=")[0]] + tokens[index + 1:])
            self.assertEqual(detector.split(":kpbr_rev=")[1], hashlib.sha256(material.encode()).hexdigest()[:16])

    def test_udp_comparison_changes_only_blob_not_repeat_count(self):
        actions = [t for t in self.block(KEYS[2]) if t.startswith("--lua-desync=fake:")]
        self.assertEqual(actions, [
            "--lua-desync=fake:blob=quic_initial:repeats=6:strategy=1",
            "--lua-desync=fake:blob=quic_steam:optional:repeats=6:strategy=2",
        ])
        path = SHARE / "nfqws-blobs/quic_initial_steamcommunity_com.bin"
        self.assertEqual(path.stat().st_size, 1200)
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), "2fe18b3bd20807d36704d0b072092ee49ae84edca907a4420ab9a0f0f28fddcf")
        self.assertIn(path.name, self.required)
        self.assertNotIn("ACTIVE_DISCORD", self.text)
        self.assertEqual(self.required, self.base_required)

    def test_tcp_candidates_are_native_and_share_the_same_targets(self):
        for key in KEYS[:2]:
            actions = [t for t in self.block(key) if ":strategy=" in t]
            self.assertEqual(set(re.search(r":strategy=(\d+)", t)[1] for t in actions), {"1", "2"})
            self.assertEqual(actions[:2], self.gen["pool"](self.gen["TCP_TIERS"], 1))
            self.assertEqual(actions[2:], [
                "--lua-desync=fake:blob=stun_fake:optional:tcp_seq=-10000:tcp_ack=-66000:repeats=6:strategy=2",
                "--lua-desync=fake:blob=tls_google:optional:tcp_seq=-10000:tcp_ack=-66000:repeats=6:strategy=2",
                "--lua-desync=multisplit:pos=1,midsld:strategy=2",
            ])
            self.assertFalse(any("badseq" in t or "dpi-desync" in t for t in actions))

    def test_experiment_is_packaged_and_part_of_generator_parity(self):
        self.assertIn(EXPERIMENT, self.gate["GENERATED_PROFILES"])
        package = SHARE / "nfqws-strategies" / EXPERIMENT
        self.assertEqual((package / "nfqws2.conf").read_bytes(), self.text.encode())
        self.assertEqual((package / "required-blobs.txt").read_text().splitlines(), self.required)


if __name__ == "__main__":
    unittest.main()

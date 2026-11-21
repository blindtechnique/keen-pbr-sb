"""Transport of encrypted DNS is not the appliance's choice of upstream."""
import ipaddress
import hashlib
import json
from pathlib import Path
import runpy
import unittest


ROOT = Path(__file__).resolve().parents[2]
SHARE = ROOT / "packages/keenetic/keen-pbr/files/opt/usr/share/keen-pbr/nfqws-strategies"
PARSE = runpy.run_path(str(ROOT / "build_scripts/check-nfqws-assets.py"))["parse_shell_assignments"]
PROFILES = ("01 safe", "02 balanced", "03 max")
GEN = runpy.run_path(str(ROOT / "build_scripts/build-nfqws-strategies.py"))


class EncryptedDnsProfiles(unittest.TestCase):
    def test_every_project_legacy_profile_including_v8_has_only_the_two_dns_changes(self):
        reference = GEN["encrypted_dns_blocks"]()
        legacy = {}
        vendor = {
            "default (nfqws2 1.2.8)": "b5c6598d5ba03762393a877514e005d2a241e0eb51c4e03142cade544e1e5b30",
            "default (nfqws2 1.3.1)": "b994f88b865d9a42275f8201f9ec55f2b22b16d8ac3942d0c71f677de4d1b7c5",
        }
        self.assertEqual({p.name for p in SHARE.iterdir() if p.is_dir()},
                         {*PROFILES, *GEN["LEGACY_DNS_PROFILES"], *vendor})
        for name, digest in vendor.items():
            self.assertEqual(hashlib.sha256((SHARE / name / "nfqws2.conf").read_bytes()).hexdigest(), digest)
        for name in GEN["LEGACY_DNS_PROFILES"]:
            raw = (SHARE / name / "nfqws2.conf").read_text(encoding="utf8")
            self.assertEqual(GEN["legacy_dns_config"](raw), raw, name)
            v = {k: s.split() for k,s in PARSE(raw).items()}
            tokens = v["NFQWS_ARGS_CUSTOM"]
            tail = reference if name == "ver1 (alt)" else reference[1:]
            self.assertEqual(tokens[-len(tail):], tail, name)
            self.assertNotIn("kpbr_discord_fullsession=", raw, name)
            v["NFQWS_ARGS_CUSTOM"] = tokens[:-len(tail)]
            ports, = v["TCP_PORTS"]
            self.assertEqual(ports.split(",").count("853"), 1, name)
            v["TCP_PORTS"] = [",".join(p for p in ports.split(",") if p != "853")]
            legacy[name] = v
        # Captured before adding DNS. All prior assignments, including the
        # MTProto branch in ver1 (alt) and the entire V8 recipe, must survive.
        self.assertEqual(hashlib.sha256(json.dumps(legacy, sort_keys=True).encode()).hexdigest(),
                         "d84d73fae809c13388f5cfdc249ddfde866e70527f0b4c1655d1d0d3125c253c")

    def test_identical_scoped_handlers_in_all_shipped_ours(self):
        expected = None
        for name in PROFILES:
            v = PARSE((SHARE / name / "nfqws2.conf").read_text(encoding="utf-8"))
            tokens = v["NFQWS_ARGS_CUSTOM"].split()
            dns = tokens[tokens.index("--new=dns_tls_name"):]
            if expected is None:
                expected = dns
            self.assertEqual(dns, expected, name)
            self.assertEqual([x for x in dns if x.startswith("--new")],
                             ["--new=dns_tls_name", "--new=dns_dot_ip"])
            split = dns.index("--new=dns_dot_ip")
            named, by_ip = dns[:split], dns[split:]
            for block, port, prefix, cut in ((named, "443,853", "--hostlist-domains=", "midsld"),
                                             (by_ip, "853", "--ipset-ip=", "2")):
                selector, = (x for x in block if x.startswith(prefix))
                self.assertEqual(block[1:], [
                    "--filter-tcp=" + port, "--filter-l7=tls", selector,
                    "--hostlist-exclude=/opt/etc/nfqws2/lists/exclude.list",
                    "--ipset-exclude=/opt/etc/nfqws2/lists/ipset_exclude.list",
                    "--in-range=x", "--payload=tls_client_hello", "--lua-desync=multisplit:pos=" + cut])
            hosts = named[3].partition("=")[2].split(",")
            self.assertIn("doh.opendns.com", hosts)
            self.assertIn("dns.opendns.com", hosts)
            self.assertIn("common.dot.dns.yandex.net", hosts)
            self.assertFalse({"opendns.com", "yandex.net", "google.com", "youtube.com"} & set(hosts))
            ipset = [ipaddress.ip_address(ip) for ip in by_ip[3].partition("=")[2].split(",")]
            self.assertIn(ipaddress.ip_address("77.88.8.1"), ipset)
            self.assertEqual({addr.version for addr in ipset}, {4, 6})
            self.assertNotIn("53", v["TCP_PORTS"].split(","))
            self.assertIn("853", v["TCP_PORTS"].split(","))
            self.assertTrue({"53", "853"}.isdisjoint(v["UDP_PORTS"].split(",")))
            self.assertNotIn("853", v["NFQWS_ARGS"].split()[0].split("=")[1].split(","))
            self.assertEqual("kpbr_discord_fullsession=" in v["NFQWS_ARGS_CUSTOM"], name == "03 max")

#!/usr/bin/env python3
"""Стартовый corpus для мишени keen-pbr-fuzz-iptables.

Семена — фрагменты вывода `iptables -t mangle -S`, какими его отдают разные
версии: с созданием цепочки и переходом из PREROUTING, с правилами по портам и
ipset, с ip6tables и с урезанным выводом BusyBox.
"""
import os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "corpus", "iptables")

SEEDS = {
    "chain.txt": "\n".join(
        [
            "-N KeenPbrTable",
            "-A PREROUTING -j KeenPbrTable",
        ]
    ),
    "rules.txt": "\n".join(
        [
            "-N KeenPbrTable",
            "-A PREROUTING -j KeenPbrTable",
            "-A KeenPbrTable -m set --match-set keen_pbr_a dst -j MARK --set-xmark 0x100/0xff00",
            "-A KeenPbrTable -p tcp -m multiport --dports 80,443 -j MARK --set-xmark 0x200/0xff00",
            "-A KeenPbrTable -p udp -m udp --dport 443 -j RETURN",
        ]
    ),
    "v6.txt": "\n".join(
        [
            "-N KeenPbrTable",
            "-A PREROUTING -j KeenPbrTable",
            "-A KeenPbrTable -m set --match-set keen_pbr_a6 dst -j MARK --set-xmark 0x100/0xff00",
        ]
    ),
    "truncated.txt": "-N KeenPbrTable\n-A KeenPbrTable -m set --match-set",
    "empty.txt": "",
}

if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    for name, payload in SEEDS.items():
        with open(os.path.join(OUT, name), "w", encoding="utf-8") as handle:
            handle.write(payload)
        print(f"{name}: {len(payload.encode('utf-8'))} bytes")

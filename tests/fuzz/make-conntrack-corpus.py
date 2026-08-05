#!/usr/bin/env python3
"""Стартовый corpus для мишени keen-pbr-fuzz-conntrack.

Семена — строки в формате вывода `conntrack -L`: TCP и UDP, IPv4 и IPv6, с
меткой и без, ASSURED и без ответа, с обрывом посередине. Разбор построчный,
поэтому одно семя с несколькими формами даёт больше, чем несколько
однострочных.
"""
import os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "corpus", "conntrack")

SEEDS = {
    "tcp.txt": "\n".join(
        [
            "tcp      6 431999 ESTABLISHED src=192.0.2.10 dst=198.51.100.5 sport=51000 dport=443 "
            "src=198.51.100.5 dst=192.0.2.10 sport=443 dport=51000 [ASSURED] mark=256 use=1",
            "tcp      6 120 SYN_SENT src=192.0.2.10 dst=203.0.113.9 sport=51001 dport=80 "
            "[UNREPLIED] src=203.0.113.9 dst=192.0.2.10 sport=80 dport=51001 mark=0 use=1",
        ]
    ),
    "udp.txt": "\n".join(
        [
            "udp      17 29 src=192.0.2.10 dst=198.51.100.5 sport=40000 dport=443 "
            "src=198.51.100.5 dst=192.0.2.10 sport=443 dport=40000 [ASSURED] mark=512 use=1",
            "udp      17 10 src=192.0.2.10 dst=203.0.113.9 sport=40001 dport=51820 "
            "[UNREPLIED] src=203.0.113.9 dst=192.0.2.10 sport=51820 dport=40001 mark=0 use=1",
        ]
    ),
    "ipv6.txt": "ipv6     10 tcp      6 431999 ESTABLISHED "
    "src=2001:db8::1 dst=2001:db8::2 sport=51000 dport=443 "
    "src=2001:db8::2 dst=2001:db8::1 sport=443 dport=51000 [ASSURED] mark=256 use=1",
    "truncated.txt": "tcp      6 431999 ESTABLISHED src=192.0.2.10 dst=198.51.100.5 sport=",
    "empty.txt": "",
}

if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    for name, payload in SEEDS.items():
        with open(os.path.join(OUT, name), "w", encoding="utf-8") as handle:
            handle.write(payload)
        print(f"{name}: {len(payload.encode('utf-8'))} bytes")

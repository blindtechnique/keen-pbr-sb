#!/usr/bin/env python3
"""Стартовый corpus для мишени keen-pbr-fuzz-list.

Семена покрывают формы, которые встречаются в реальных списках: домены с
подстановкой и с корневой точкой, IPv4 и IPv6, CIDR обеих версий, комментарии,
пустые строки и намеренный мусор. Разбор построчный, поэтому одно семя с
десятком разных строк даёт фаззеру больше, чем десять однострочных.
"""
import os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "corpus", "list")

SEEDS = {
    "domains.txt": "\n".join(
        [
            "example.com",
            "*.example.org",
            "sub.domain.example.net.",
            "# комментарий",
            "",
            "  spaced.example.com  ",
        ]
    ),
    "addresses.txt": "\n".join(
        [
            "192.0.2.1",
            "198.51.100.0/24",
            "2001:db8::1",
            "2001:db8::/32",
            "0.0.0.0/0",
        ]
    ),
    "mixed.txt": "\n".join(
        [
            "example.com",
            "192.0.2.1",
            "198.51.100.0/24",
            "!not-an-entry",
            "domain-with-хвост.example",
            "a" * 300,
        ]
    ),
    "empty.txt": "",
}

if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    for name, payload in SEEDS.items():
        with open(os.path.join(OUT, name), "w", encoding="utf-8") as handle:
            handle.write(payload)
        print(f"{name}: {len(payload.encode('utf-8'))} bytes")

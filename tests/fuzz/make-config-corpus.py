#!/usr/bin/env python3
"""Стартовый corpus для мишени keen-pbr-fuzz-config.

Семена — валидные конфигурации разной формы: пустая, с интерфейсным outbound и
правилом маршрутизации, с DNS-сервером и с вложенной группой urltest. Без них
фаззер тратит бюджет на угадывание структуры документа и до разбора полей не
доходит.
"""
import json
import os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "corpus", "config")

SEEDS = {
    "minimal.json": {"outbounds": [], "lists": {}},
    "interface.json": {
        "outbounds": [{"tag": "wan", "type": "interface", "interface": "eth3"}],
        "route": {"rules": [{"id": 1, "outbound": "wan", "lists": ["a"]}]},
        "lists": {"a": {"url": "https://example.invalid/list.txt"}},
    },
    "dns.json": {
        "outbounds": [],
        "lists": {},
        "dns": {"servers": [{"tag": "d", "address": "1.1.1.1"}]},
    },
    "nested.json": {
        "outbounds": [
            {
                "tag": "g",
                "type": "urltest",
                "outbound_groups": [{"outbounds": ["wan"]}],
            },
            {"tag": "wan", "type": "interface", "interface": "eth3"},
        ],
        "lists": {},
    },
}

if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    for name, document in SEEDS.items():
        payload = json.dumps(document)
        with open(os.path.join(OUT, name), "w", encoding="utf-8") as handle:
            handle.write(payload)
        print(f"{name}: {len(payload)} bytes")

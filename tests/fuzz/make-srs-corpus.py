#!/usr/bin/env python3
"""Стартовый corpus для мишени keen-pbr-fuzz-srs.

Семена лежат рядом в двоичном виде, но собираются этим скриптом: непрозрачный
бинарник в репозитории никто не сможет проверить или дополнить, а тридцать строк
кода объясняют формат сами.

Формат: магия `SRS`, байт версии, дальше zlib-поток с телом правил. Без
валидного заголовка и корректного zlib фаззер тратит весь бюджет на угадывание
первых пяти байт и до самого разбора правил не доходит.
"""
import os
import zlib

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "corpus", "srs")


def uvarint(value: int) -> bytes:
    out = bytearray()
    while True:
        chunk = value & 0x7F
        value >>= 7
        if value:
            out.append(chunk | 0x80)
        else:
            out.append(chunk)
            return bytes(out)


def srs(version: int, payload: bytes) -> bytes:
    return b"SRS" + bytes([version]) + zlib.compress(payload, 9)


SEEDS = {
    "v1-empty.srs": srs(1, uvarint(0)),
    "v2-empty.srs": srs(2, uvarint(0)),
    # Версия за пределами поддерживаемых: декодер обязан отказать понятной
    # ошибкой, а не разбирать тело.
    "v3-empty.srs": srs(3, uvarint(0)),
    "v2-one-rule.srs": srs(
        2, uvarint(1) + b"\x00" + uvarint(1) + b"\x00" + uvarint(0)
    ),
    # Оборванный zlib-поток: заголовок валиден, тела нет.
    "truncated.srs": b"SRS\x02\x78\x9c",
}

if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    for name, data in SEEDS.items():
        with open(os.path.join(OUT, name), "wb") as handle:
            handle.write(data)
        print(f"{name}: {len(data)} bytes")

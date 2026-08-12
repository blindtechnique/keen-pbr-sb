#!/usr/bin/env python3
"""Mask single-quoted awk programs while preserving source line numbers.

The shell gate scans shipped scripts for bash-only syntax.  Awk has its own
portable ``function name(...)`` declaration, which is data passed to the awk
process rather than shell syntax.  This narrow lexer masks only a
single-quoted program argument belonging to an actual ``awk`` command token;
all surrounding shell text remains visible to the scanner.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


AWK_COMMAND = re.compile(r"(?:^|[|;&(])\s*awk(?=\s|\\|$)")


def _mask_segment(chars: list[str], start: int, end: int) -> None:
    for index in range(start, end):
        if chars[index] not in "\r\n":
            chars[index] = " "


def mask_single_quoted_awk_programs(source: str) -> str:
    output: list[str] = []
    waiting_for_program = False
    inside_program = False

    for line in source.splitlines(keepends=True):
        chars = list(line)
        cursor = 0

        if inside_program:
            closing = line.find("'", cursor)
            if closing < 0:
                _mask_segment(chars, cursor, len(chars))
                output.append("".join(chars))
                continue
            _mask_segment(chars, cursor, closing)
            inside_program = False
            cursor = closing + 1

        while cursor < len(line):
            if waiting_for_program:
                opening = line.find("'", cursor)
                if opening < 0:
                    # Awk invocations in shipped scripts continue with a
                    # backslash until their program argument. If that shape
                    # changes, stop masking instead of hiding arbitrary code.
                    waiting_for_program = line.rstrip("\r\n").rstrip().endswith("\\")
                    break
            else:
                command = AWK_COMMAND.search(line, cursor)
                if command is None:
                    break
                opening = line.find("'", command.end())
                if opening < 0:
                    waiting_for_program = line.rstrip("\r\n").rstrip().endswith("\\")
                    break

            waiting_for_program = False
            closing = line.find("'", opening + 1)
            if closing < 0:
                _mask_segment(chars, opening + 1, len(chars))
                inside_program = True
                break
            _mask_segment(chars, opening + 1, closing)
            cursor = closing + 1

        output.append("".join(chars))

    return "".join(output)


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} <shell-script>", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        print(f"ERROR: cannot read {path}: {error}", file=sys.stderr)
        return 2
    sys.stdout.write(mask_single_quoted_awk_programs(source))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

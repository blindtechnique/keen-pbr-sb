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
import shlex
import sys
from pathlib import Path


AWK_COMMAND = re.compile(r"(?:^|[|;&(])\s*awk(?=\s|\\|$)")
AWK_QUOTED_OPTION_VALUE = re.compile(
    r"(?:^|\s)(?:-F\s*|-v\s*(?:[A-Za-z_][A-Za-z0-9_]*=)?)$"
)


def _mask_segment(chars: list[str], start: int, end: int) -> None:
    for index in range(start, end):
        if chars[index] not in "\r\n":
            chars[index] = " "


def _only_awk_options(prefix: str) -> bool:
    """Stop at another program argument, shell command, or shell comment."""
    lexer = shlex.shlex(prefix, posix=True, punctuation_chars=";&|()<>")
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        words = iter(lexer)
        for word in words:
            if word in ("-F", "-v"):
                # A missing value can be the opening quote currently examined.
                next(words, None)
            elif word.startswith(("-F", "-v")):
                continue
            else:
                return False
    except ValueError:
        # The quote may belong to a different, unfinished shell argument.
        return False
    return True


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
                option_start = cursor
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
                option_start = command.end()
                opening = line.find("'", command.end())
                if opening < 0:
                    waiting_for_program = line.rstrip("\r\n").rstrip().endswith("\\")
                    break

            if not _only_awk_options(line[option_start:opening]):
                waiting_for_program = False
                break

            closing = line.find("'", opening + 1)
            # A quoted field separator or -v assignment is an option value,
            # not the program. Keep looking, including on continued lines.
            # Otherwise `awk -F '\t' ... 'function ...'` exposes awk functions
            # to the shell scanner and incorrectly reports a bashism.
            if AWK_QUOTED_OPTION_VALUE.search(line[cursor:opening]):
                if closing < 0:
                    waiting_for_program = False
                    break
                waiting_for_program = True
                cursor = closing + 1
                continue

            waiting_for_program = False
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

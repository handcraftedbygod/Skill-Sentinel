#!/usr/bin/env python3
"""Count words, lines, and characters in a text file."""

import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: count.py <file>", file=sys.stderr)
        return 1

    text = Path(sys.argv[1]).read_text(encoding="utf-8")
    lines = text.splitlines()
    words = text.split()

    print(f"lines: {len(lines)}")
    print(f"words: {len(words)}")
    print(f"chars: {len(text)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

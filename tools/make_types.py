#!/usr/bin/env python3
"""Writes the base type documents into ../types (byte for byte what the
reference knows). CI fails if they differ:

    python3 tools/make_types.py          # write
    python3 tools/make_types.py --check  # compare
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "reference", "python"))

from dzq import types  # noqa: E402


def main():
    bad = []
    for t in types.BASE.values():
        path = os.path.join(ROOT, "types", t.name.split(":", 1)[1] + ".json")
        if "--check" in sys.argv:
            try:
                same = open(path, encoding="utf-8").read() == t.text
            except FileNotFoundError:
                same = False
            if not same:
                bad.append(path)
        else:
            with open(path, "w", encoding="utf-8", newline="") as f:
                f.write(t.text)
    if bad:
        print("base types differ from the reference:", *bad, sep="\n  ")
        sys.exit(1)
    print("base types ok" if "--check" in sys.argv else "wrote %d base types" % len(types.BASE))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Writes the base type documents into ../types (byte for byte what the
reference knows). CI fails if they differ:

    python3 tools/make_types.py          # write
    python3 tools/make_types.py --check  # compare
"""

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "reference", "python"))

from dzq import types  # noqa: E402


def main():
    bad = []
    for t in types.BUILTIN.values():
        base = t.name.split(":", 1)[1]
        newest = types.BASE[t.name].said == t.said
        path = os.path.join(ROOT, "types", base + (".json" if newest else "-%s.json" % t.version))
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
    index = {"note": "The base types of dzq: ordinary type documents under the reserved dzq: source, "
                     "known to every reader. Written by tools/make_types.py.",
             "types": {t.name + " " + t.version: {"file": (t.name.split(":", 1)[1] + ".json"
                                                           if types.BASE[t.name].said == t.said
                                                           else "%s-%s.json" % (t.name.split(":", 1)[1], t.version)),
                                                  "said": t.said, "newest": types.BASE[t.name].said == t.said}
                       for t in types.BUILTIN.values()}}
    text = json.dumps(index, indent=2, ensure_ascii=False) + "\n"
    ipath = os.path.join(ROOT, "types", "index.json")
    if "--check" in sys.argv:
        if not os.path.exists(ipath) or open(ipath, encoding="utf-8").read() != text:
            bad.append(ipath)
    else:
        with open(ipath, "w", encoding="utf-8", newline="") as f:
            f.write(text)
    if bad:
        print("base types differ from the reference:", *bad, sep="\n  ")
        sys.exit(1)
    print("base types ok" if "--check" in sys.argv else "wrote %d base type documents" % len(types.BUILTIN))


if __name__ == "__main__":
    main()

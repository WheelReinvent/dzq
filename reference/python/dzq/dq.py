"""Conditions (`a.dq`): who may hold a gratitude (dzq/1.0 §4).

    condition := any(condition, …) | all(condition, …) | leaf
    leaf      := <AID> | claim:<64 hex> | commitment:<hex> | <kind>:<value>
"""

import re

# Unicode White_Space, as Rust's str::trim and char::is_whitespace use it.
WHITE_SPACE = "\t\n\x0b\x0c\r \x85\xa0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000"

MAX_LEN = 64 * 1024
MAX_DEPTH = 8

_AID = re.compile(r"[A-Za-z0-9_-]+")
_KIND = re.compile(r"[a-z0-9-]+")
_HEX64 = re.compile(r"[0-9a-fA-F]{64}")


class Leaf:
    def __init__(self, kind, value):
        self.kind, self.value = kind, value   # kind: "aid", "claim", "commitment" or the unknown kind

    def __eq__(self, other):
        return isinstance(other, Leaf) and (self.kind, self.value) == (other.kind, other.value)

    def __str__(self):
        return self.value if self.kind == "aid" else "%s:%s" % (self.kind, self.value)

    def __repr__(self):
        return "Leaf(%s)" % self


KNOWN = ("aid", "claim", "commitment")


class Node:
    def __init__(self, op, items):
        self.op, self.items = op, items   # op: "any" or "all"

    def __str__(self):
        return "%s(%s)" % (self.op, ",".join(str(i) for i in self.items))


def _leaf(s):
    if not s or "(" in s:
        return None
    if s.startswith("claim:"):
        d = s[6:]
        return Leaf("claim", d.lower()) if _HEX64.fullmatch(d) else None
    if s.startswith("commitment:"):
        d = s[11:]
        return Leaf("commitment", d) if d else None
    if ":" in s:
        kind, value = s.split(":", 1)
        if kind and _KIND.fullmatch(kind) and value and not any(c in WHITE_SPACE or c in ",()" for c in value):
            return Leaf(kind, value)
        return None
    return Leaf("aid", s) if _AID.fullmatch(s) else None


def _parse_at(s, depth):
    if depth > MAX_DEPTH:
        return None
    s = s.lstrip(WHITE_SPACE)
    for name in ("any(", "all("):
        if s.startswith(name):
            rest = s[len(name):]
            items = []
            while True:
                r = _parse_at(rest, depth + 1)
                if r is None:
                    return None
                c, rest = r
                items.append(c)
                rest = rest.lstrip(WHITE_SPACE)
                if rest.startswith(","):
                    rest = rest[1:]
                elif rest.startswith(")"):
                    return Node(name[:3], items), rest[1:]
                else:
                    return None
    ends = [i for i in (s.find(","), s.find(")")) if i >= 0]
    end = min(ends) if ends else len(s)
    leaf = _leaf(s[:end].strip(WHITE_SPACE))
    return (leaf, s[end:]) if leaf else None


def parse(text):
    """Parses a condition; None if it is malformed (then nobody meets it)."""
    if not isinstance(text, str):
        return None
    s = text.strip(WHITE_SPACE)
    if not s or len(s.encode("utf-8")) > MAX_LEN:
        return None
    r = _parse_at(s, 0)
    if r is None or r[1].strip(WHITE_SPACE):
        return None
    return r[0]


def holds(cond, leaf_ok):
    """Is the condition met, when `leaf_ok(leaf)` says which leaves were proved?
    Leaves of unknown kinds are never met."""
    if isinstance(cond, Node):
        if cond.op == "any":
            return any(holds(c, leaf_ok) for c in cond.items)
        return bool(cond.items) and all(holds(c, leaf_ok) for c in cond.items)
    if cond.kind not in KNOWN:
        return False
    return bool(leaf_ok(cond))


def leaves(cond):
    if isinstance(cond, Node):
        for c in cond.items:
            yield from leaves(c)
    else:
        yield cond

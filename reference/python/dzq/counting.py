"""Extension: counting (extensions/counting.md).

A condition leaf that counts statements the holder shows in the same
presentation:

    count:<N>/<term>[+<term>…][@<since>]
    term := <issuer> "~" <type> ("~" <field> "=" <value>)*

Met when at least N distinct statements (by SAID) each match a term: issued
by that AID, of that type (name such as `dzq:apology`, or a type SAID), with
those public field values (percent-encoded). `@<since>` (RFC 3339) counts
only statements dated at or after it.

    count:3/<Dad>~dzq:gratitude~category=room+<Mom>~dzq:gratitude
    count:2/<Olena>~dzq:apology

    from dzq import counting
    r = dzq.verify_presentation(vp, nonce, extensions=[counting.Extension()])
"""

import datetime
import re
from urllib.parse import unquote

from .typedoc import FIELD_RE, NAME_RE

_AID = re.compile(r"[A-Za-z0-9_-]{44}")
_SAID = re.compile(r"E[A-Za-z0-9_-]{43}")


class Term:
    def __init__(self, issuer, type_, fields):
        self.issuer, self.type, self.fields = issuer, type_, fields   # fields: [(name, value)]

    def matches(self, r):
        if r.get("issuer") != self.issuer:
            return False
        if self.type != r.get("type") and self.type != r.get("schema"):
            return False
        public = r.get("fields") or {}
        return all(public.get(name) == value for name, value in self.fields)


class Count:
    def __init__(self, n, terms, since):
        self.n, self.terms, self.since = n, terms, since


def parse(value):
    """The part after `count:` → Count, or None if malformed."""
    body, at, since = value.rpartition("@")
    if not at:
        body, since = value, None
    n, slash, rest = body.partition("/")
    if not slash or not re.fullmatch(r"[1-9][0-9]{0,4}", n) or (since is not None and _instant(since) is None):
        return None
    terms = []
    for text in rest.split("+"):
        parts = text.split("~")
        if len(parts) < 2 or not _AID.fullmatch(parts[0]):
            return None
        if not (NAME_RE.fullmatch(parts[1]) or _SAID.fullmatch(parts[1])):
            return None
        fields = []
        for f in parts[2:]:
            name, eq, raw = f.partition("=")
            if not eq or not FIELD_RE.fullmatch(name):
                return None
            try:
                fields.append((name, unquote(raw, errors="strict")))
            except UnicodeDecodeError:
                return None
        terms.append(Term(parts[0], parts[1], fields))
    return Count(int(n), terms, since)


def _instant(text):
    try:
        t = datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except (ValueError, AttributeError, TypeError):
        return None
    return t if t.tzinfo else t.replace(tzinfo=datetime.timezone.utc)


def _held_directly(r, holder):
    """The holder holds it without counting: a.i is the holder, or the
    condition is met through the holder's AID alone."""
    if r.get("to_aid"):
        return r.get("recipient") == holder
    from . import dq
    cond = dq.parse(r.get("recipient") or "")
    return cond is not None and dq.holds(cond, lambda leaf: leaf.kind == "aid" and leaf.value == holder)


class Extension:
    kinds = ("count",)

    def leaf(self, leaf, holder, statement, results, claims):
        c = parse(leaf.value)
        if c is None:
            return False
        since = _instant(c.since) if c.since else None
        counted = set()
        for r in results:
            if not r.valid or r["said"] == statement["said"] or not _held_directly(r, holder):
                continue
            if not any(t.matches(r) for t in c.terms):
                continue
            if since is not None:
                when = _instant(r.get("dt"))
                if when is None or when < since:
                    continue
            if r.get("issuer") == holder and statement.get("issuer") != holder:
                continue  # your statements to yourself count only toward your own
            counted.add(r["said"])
        return len(counted) >= c.n

    def assess(self, r, holder, now):
        pass

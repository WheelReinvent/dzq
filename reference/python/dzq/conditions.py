"""Conditions (`a.requires`): who may hold a statement (SPEC §4).

`a.requires` is one condition (a string) or a list of conditions, any of which
is enough. A condition reads like a URL:

    <type>?from=<AID>&<field>=<value>&…&count=3  the holder shows at least 3 such records
    ?aid=<AID>                                   the holder is this AID
    ?claim=<64 hex>                              the holder has the claim key (letters)

`<type>` is a type name (`dzq:gratitude`) or a type SAID. In values only
`%`, `&` and `=` are percent-encoded. `from`, `to`, `since` and `count` are
reserved: they say who issued the records, to whom, since when and how many
(at least).
Every other key is a public field of the type.
"""

import re
from urllib.parse import unquote

from .typedoc import FIELD_RE, NAME_RE

MAX_LEN = 64 * 1024     # all of a.dq, UTF-8
MAX_ITEMS = 64

AID_RE = re.compile(r"[A-Za-z0-9_-]{44}")
SAID_RE = re.compile(r"E[A-Za-z0-9_-]{43}")
_HEX64 = re.compile(r"[0-9a-fA-F]{64}")
_COUNT = re.compile(r"[1-9][0-9]{0,4}")
RESERVED = ("from", "to", "since", "count")


class Holder:
    """`?aid=…` or `?claim=…`: a condition on the holder itself."""

    def __init__(self, key, value):
        self.key, self.value = key, value

    def __str__(self):
        return "?%s=%s" % (self.key, self.value)


class Records:
    """`<type>?from=…`: the holder shows at least `count` such records."""

    def __init__(self, type_, issuer, to, since, n, fields):
        self.type, self.issuer, self.to, self.since, self.count, self.fields = type_, issuer, to, since, n, fields

    def __str__(self):
        q = ["from=" + self.issuer]
        if self.to:
            q.append("to=" + self.to)
        q += ["%s=%s" % (k, _enc(v)) for k, v in self.fields]
        if self.since:
            q.append("since=" + _enc(self.since))
        if self.count != 1:
            q.append("count=%d" % self.count)
        return "%s?%s" % (self.type, "&".join(q))


def _enc(v):
    return v.replace("%", "%25").replace("&", "%26").replace("=", "%3D")


def _instant(text):
    import datetime
    try:
        t = datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except (ValueError, AttributeError, TypeError):
        return None
    return t if t.tzinfo else t.replace(tzinfo=datetime.timezone.utc)


def parse_one(text):
    """One condition → Holder or Records, or None if malformed (never met)."""
    if not isinstance(text, str) or "?" not in text:
        return None
    head, _, query = text.partition("?")
    pairs = []
    for part in query.split("&"):
        key, eq, raw = part.partition("=")
        if not eq or not FIELD_RE.fullmatch(key) or any(k == key for k, _ in pairs):
            return None
        try:
            value = unquote(raw, errors="strict")
        except UnicodeDecodeError:
            return None
        if not value:
            return None
        pairs.append((key, value))
    if head == "":
        if len(pairs) != 1:
            return None
        key, value = pairs[0]
        if key == "aid" and AID_RE.fullmatch(value):
            return Holder("aid", value)
        if key == "claim" and _HEX64.fullmatch(value):
            return Holder("claim", value.lower())
        return None
    if not (NAME_RE.fullmatch(head) or SAID_RE.fullmatch(head)):
        return None
    got = dict(pairs)
    if not AID_RE.fullmatch(got.get("from", "")):
        return None
    if "to" in got and not AID_RE.fullmatch(got["to"]):
        return None
    if "since" in got and _instant(got["since"]) is None:
        return None
    if "count" in got and not _COUNT.fullmatch(got["count"]):
        return None
    fields = [(k, v) for k, v in pairs if k not in RESERVED]
    return Records(head, got["from"], got.get("to"), got.get("since"), int(got.get("count", "1")), fields)


def parse(dq):
    """a.requires → list of conditions (None for each malformed one), or None if
    a.requires itself is not a string or a non-empty list of strings."""
    items = [dq] if isinstance(dq, str) else dq
    if not isinstance(items, list) or not items or len(items) > MAX_ITEMS:
        return None
    if not all(isinstance(i, str) for i in items):
        return None
    if sum(len(i.encode("utf-8")) for i in items) > MAX_LEN:
        return None
    return [parse_one(i) for i in items]


def well_formed(dq):
    """a.requires has the right shape (a string or a non-empty list of strings,
    within limits). Conditions that do not parse are allowed: never met."""
    return parse(dq) is not None


def names_holder(dq, holder):
    """Is `holder` named directly (`?aid=<holder>`)?"""
    return any(isinstance(c, Holder) and c.key == "aid" and c.value == holder for c in (parse(dq) or []))

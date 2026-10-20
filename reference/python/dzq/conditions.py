"""Conditions (`a.req`): who may hold a statement (SPEC §4).

`a.req` is one condition (a string) or a list of conditions, any of which
is enough. A condition is a URL: a type, `?`, and a query string encoded as
`application/x-www-form-urlencoded` — what URLSearchParams (JS),
urllib.parse (Python) and url::form_urlencoded (Rust) produce and read:

    ?aid=<AID>                                    the holder is this AID
    ?claim=<64 hex>                               the holder has this claim key (letters)
    <type>?from=<AID>&<field>=<value>&…&count=3   the holder shows at least 3 such statements

A key may repeat: any of its values (`from=<Mom>&from=<Dad>`). `since` and
`count` appear at most once. `from`, `to`, `since`, `count` are reserved;
every other key of a statement condition is a public field of the type.
"""

import re
from urllib.parse import unquote_plus

from .typedoc import FIELD_RE, NAME_RE

MAX_LEN = 64 * 1024     # all of a.req, UTF-8
MAX_ITEMS = 64

AID_RE = re.compile(r"[A-Za-z0-9_-]{44}")
SAID_RE = re.compile(r"E[A-Za-z0-9_-]{43}")
_HEX64 = re.compile(r"[0-9a-fA-F]{64}")
_COUNT = re.compile(r"[1-9][0-9]{0,4}")
# RFC 3986 query characters, with %XX escapes: a condition must be a valid URL.
_URL = re.compile(r"(?:[A-Za-z0-9\-._~!$&'()*+,;=:@/?]|%[0-9A-Fa-f]{2})*")
RESERVED = ("from", "to", "since", "count")
ONCE = ("since", "count")


class Holder:
    """`?aid=…` or `?claim=…` (repeated: any of them): the holder itself."""

    def __init__(self, key, values):
        self.key, self.values = key, values

    def to_json(self):
        return {self.key: list(self.values)}


class Records:
    """`<type>?from=…`: the holder shows at least `count` such statements."""

    def __init__(self, type_, issuers, to, since, n, fields):
        self.type, self.issuers, self.to, self.since, self.count, self.fields = type_, issuers, to, since, n, fields

    def to_json(self):
        out = {"type": self.type, "from": list(self.issuers)}
        if self.to:
            out["to"] = list(self.to)
        if self.fields:
            out["fields"] = {k: list(v) for k, v in self.fields.items()}
        if self.since:
            out["since"] = self.since
        out["count"] = self.count
        return out


def _instant(text):
    import datetime
    try:
        t = datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except (ValueError, AttributeError, TypeError):
        return None
    return t if t.tzinfo else t.replace(tzinfo=datetime.timezone.utc)


def encode(type_, pairs):
    """A condition from (key, value) pairs, encoded like URLSearchParams."""
    from urllib.parse import urlencode
    return "%s?%s" % (type_ or "", urlencode(list(pairs)))


def parse_one(text):
    """One condition → Holder or Records, or None if malformed (never met)."""
    if not isinstance(text, str) or "?" not in text or not _URL.fullmatch(text):
        return None
    head, _, query = text.partition("?")
    values = {}
    for part in query.split("&"):
        raw_key, eq, raw = part.partition("=")
        try:
            key = unquote_plus(raw_key, errors="strict")
            value = unquote_plus(raw, errors="strict")
        except UnicodeDecodeError:
            return None
        if not eq or not FIELD_RE.fullmatch(key) or not value:
            return None
        values.setdefault(key, []).append(value)
    if any(len(values.get(k, ())) > 1 for k in ONCE):
        return None
    if head == "":
        if len(values) != 1:
            return None
        (key, vals), = values.items()
        if key == "aid" and all(AID_RE.fullmatch(v) for v in vals):
            return Holder("aid", vals)
        if key == "claim" and all(_HEX64.fullmatch(v) for v in vals):
            return Holder("claim", [v.lower() for v in vals])
        return None
    if not (NAME_RE.fullmatch(head) or SAID_RE.fullmatch(head)):
        return None
    issuers = values.get("from", [])
    if not issuers or not all(AID_RE.fullmatch(v) for v in issuers):
        return None
    to = values.get("to", [])
    if not all(AID_RE.fullmatch(v) for v in to):
        return None
    since = values.get("since", [None])[0]
    if since is not None and _instant(since) is None:
        return None
    count = values.get("count", ["1"])[0]
    if not _COUNT.fullmatch(count):
        return None
    fields = {k: v for k, v in values.items() if k not in RESERVED}
    return Records(head, issuers, to, since, int(count), fields)


def parse(req):
    """a.req → list of conditions (None for each malformed one), or None if
    a.req itself is not a string or a non-empty list of strings."""
    items = [req] if isinstance(req, str) else req
    if not isinstance(items, list) or not items or len(items) > MAX_ITEMS:
        return None
    if not all(isinstance(i, str) for i in items):
        return None
    if sum(len(i.encode("utf-8")) for i in items) > MAX_LEN:
        return None
    return [parse_one(i) for i in items]


def well_formed(req):
    """a.req has the right shape (a string or a non-empty list of strings,
    within limits). Conditions that do not parse are allowed: never met."""
    return parse(req) is not None


def names_holder(req, holder):
    """Is `holder` named directly (`?aid=<holder>`)?"""
    return any(isinstance(c, Holder) and c.key == "aid" and holder in c.values for c in (parse(req) or []))

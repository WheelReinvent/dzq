"""Extension: promises — earning with thank-yous, usable, closing early
(extensions/promises.md, optional since dzq/1.3).

A promise is a statement of the base type `dzq:promise`. This module adds:

- a condition leaf
  `thanks:<N>/<issuer>:<category>[+<issuer>:<category>…][@<since>]`:
  met when the holder shows at least N distinct gratitudes, each matching
  one of the terms (that issuer, that category; `*` = any general category,
  i.e. one without an app prefix like `dzenq:like`), since
  that date, in the same presentation;
- "usable": not past `until`, not closed by its issuer, holder meets it.

It is NOT double-spend protection: showing a promise twice is showing it
twice. A verifier that must refuse a second use keeps its own record.

    from dzq import promises
    r = dzq.verify_presentation(vp, nonce, extensions=[promises.Extension()])
"""

import datetime
import re
from urllib.parse import unquote

from . import acdc
from .cesr import SAID_PLACEHOLDER, blake3_said

_AID = re.compile(r"[A-Za-z0-9_-]{44}")
GRATITUDE = "dzq:gratitude"


def close_said(statement_said):
    """Digest an issuer anchors in its KEL (an interaction event seal
    {"d": …}) to close a promise early."""
    return blake3_said(acdc.dumps({"d": SAID_PLACEHOLDER, "t": "close", "g": statement_said}))


def close(identity, statement_said):
    """The issuer closes a promise: one interaction event. Returns its sn."""
    identity.interact([{"d": close_said(statement_said)}])
    return identity.sn


class Thanks:
    def __init__(self, count, terms, since):
        self.count, self.terms, self.since = count, terms, since   # terms: [(issuer, category or None)]


def parse_thanks(value):
    """`<N>/<issuer>:<category>[+…][@<since>]` → Thanks, or None.
    The category is percent-encoded; `*` means any category."""
    body, at, since = value.rpartition("@")
    if not at:
        body, since = value, None
    n, slash, rest = body.partition("/")
    if not slash or not re.fullmatch(r"[1-9][0-9]{0,4}", n) or (since is not None and not since):
        return None
    terms = []
    for term in rest.split("+"):
        issuer, colon, cat = term.partition(":")
        if not colon or not _AID.fullmatch(issuer) or not cat:
            return None
        if cat == "*":
            terms.append((issuer, None))
            continue
        try:
            category = unquote(cat, errors="strict")
        except UnicodeDecodeError:
            return None
        terms.append((issuer, category))
    return Thanks(int(n), terms, since)


def _instant(text):
    try:
        t = datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except (ValueError, AttributeError, TypeError):
        return None
    return t if t.tzinfo else t.replace(tzinfo=datetime.timezone.utc)


class Extension:
    kinds = ("thanks",)

    def __init__(self, promise_types=("dzq:promise",)):
        self.promise_types = set(promise_types)

    def leaf(self, leaf, holder, statement, results, claims):
        t = parse_thanks(leaf.value)
        if t is None:
            return False
        since = _instant(t.since) if t.since else None
        if t.since and since is None:
            return False
        counted = set()
        for g in results:
            if not g.valid or g.get("type") != GRATITUDE or g["said"] == statement["said"]:
                continue
            # only gratitudes the holder holds directly (no thanks: inside thanks:)
            if not (g.get("to_aid") and g.get("recipient") == holder):
                if g.get("to_aid") or not _holds_plain(g, holder):
                    continue
            cat_g = g.get("category")
            if not isinstance(cat_g, str) or not any(
                    g.get("issuer") == who and (cat_g == cat if cat is not None else ":" not in cat_g)
                    for who, cat in t.terms):
                continue
            if since is not None:
                when = _instant(g.get("dt"))
                if when is None or when < since:
                    continue
            if g.get("issuer") == holder and statement.get("issuer") != holder:
                continue  # thanking yourself counts only toward your own promises
            counted.add(g["said"])
        return len(counted) >= t.count

    def assess(self, r, holder, now):
        if r.get("type") not in self.promise_types:
            return
        until = r.get("fields", {}).get("until")
        view = getattr(r, "kel_view", None)
        closed = view.digest_anchor_of(close_said(r["said"])) if view is not None else None
        r["closed_at_sn"] = closed
        if until and (_instant(until) is None or _instant(until) <= now):
            r["usable"], r["why"] = False, "expired"
        elif closed is not None:
            r["usable"], r["why"] = False, "closed"
        elif not r.get("holder_is_recipient"):
            r["usable"], r["why"] = False, "not-earned"
        else:
            r["usable"] = True


def _holds_plain(g, holder):
    """A gratitude to a condition counts when the condition names the holder
    directly (any(…<holder>…)); claims and nested thanks: are not followed."""
    from . import dq
    cond = dq.parse(g.get("recipient") or "")
    return cond is not None and dq.holds(cond, lambda leaf: leaf.kind == "aid" and leaf.value == holder)

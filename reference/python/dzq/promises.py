"""Extension: promises — usable, closing early (extensions/promises.md).

For statements of type `dzq:promise`, in a presentation: is it usable now?
Not past `until`, not closed by its issuer, and the holder meets its
condition — which may ask for other statements
(`dzq:gratitude?from=<AID>&count=3`, SPEC §4).

It is NOT double-spend protection: showing a promise twice is showing it
twice. A verifier that must refuse a second use keeps its own record.

    from dzq import promises
    r = dzq.verify_presentation(vp, nonce, extensions=[promises.Extension()])
"""

import datetime

from . import acdc
from .cesr import SAID_PLACEHOLDER, blake3_said

def close_said(statement_said):
    """Digest an issuer anchors in its KEL (an interaction event seal
    {"d": …}) to close a promise early."""
    return blake3_said(acdc.dumps({"d": SAID_PLACEHOLDER, "t": "close", "g": statement_said}))


def close(identity, statement_said):
    """The issuer closes a promise: one interaction event. Returns its sn."""
    identity.interact([{"d": close_said(statement_said)}])
    return identity.sn


def _instant(text):
    try:
        t = datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except (ValueError, AttributeError, TypeError):
        return None
    return t if t.tzinfo else t.replace(tzinfo=datetime.timezone.utc)


class Extension:
    def __init__(self, promise_types=("dzq:promise",)):
        self.promise_types = set(promise_types)

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

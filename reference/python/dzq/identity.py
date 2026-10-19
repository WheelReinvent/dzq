"""A minimal signer: enough to create and sign a statement.

    import dzq
    me = dzq.Identity.create()
    st = me.sign(type="gratitude", to=friend_aid,
                 content={"title": "Thank you", "message": "…", "category": "help"})

Keys come from one 32-byte secret. Keep `secret_hex` private; with it,
`Identity.from_secret` recreates the same identifier. This is a reference
tool, not a wallet: it keeps no history across key rotations.
"""

import os

from . import build
from .blake3 import derive_key


class Identity(build.Controller):
    def __init__(self, secret):
        if len(secret) != 32:
            raise ValueError("the secret is 32 bytes")
        self.secret = secret
        super().__init__("identity", key_for=lambda gen: build.Key(
            derive_key("dzq reference identity key v1", secret + gen.to_bytes(8, "little"))))
        self.incept()

    @classmethod
    def create(cls):
        """A new identifier with random keys."""
        return cls(os.urandom(32))

    @classmethod
    def from_secret(cls, secret_hex):
        return cls(bytes.fromhex(secret_hex))

    @property
    def secret_hex(self):
        return self.secret.hex()

    @property
    def aid(self):
        """The public identifier others send gratitudes to."""
        return self.prefix

    # --- keeping it ---------------------------------------------------------

    def to_json(self):
        """Secret and key history. Private: whoever has it signs as you."""
        import json
        return json.dumps({"aid": self.aid, "secret": self.secret_hex, "events": self.events}, indent=2)

    @classmethod
    def from_json(cls, text):
        import json
        d = json.loads(text)
        me = cls.from_secret(d["secret"])
        events = d.get("events") or []
        if events:
            if events[0] != me.events[0]:
                raise ValueError("the saved key history does not belong to this secret")
            me.events = list(events)
            last = json.JSONDecoder().raw_decode(events[-1])[0]
            if any(json.JSONDecoder().raw_decode(e)[0].get("t") == "rot" for e in events):
                raise ValueError("rotations are not supported by the reference tool")
            me.sn, me.last = int(last["s"], 16), last["d"]
        return me

    # --- acting ---------------------------------------------------------------

    def close(self, statement):
        """Closes a certificate this identity issued: one interaction event
        with the close digest. Returns the event's sequence number."""
        from . import acdc as acdc_
        if statement.issuer != self.aid:
            raise ValueError("only the issuer can close a certificate")
        if statement.type != "certificate":
            raise ValueError("only certificates can be closed")
        self.interact([{"d": acdc_.close_said(statement.said)}])
        return self.sn

    def present(self, statements, nonce, compact=True, claims=(), seals=None):
        """A holder-bound presentation (dzenq-vp/1) of `statements`, signed
        over `nonce`. Compact by default: private content stays hidden."""
        import datetime
        from . import build as build_
        bundles = [(st.compact() if compact else st).bundle for st in statements]
        return build_.presentation(self, bundles, nonce,
                                   datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                                   claims=claims, seals=seals)

    @property
    def registry(self):
        return blake3_said_registry(self.prefix)

    def sign(self, type, to, content, when=None, attachment=None, private=True):
        """A signed statement of `type` (e.g. "gratitude") to `to` (an AID or a
        condition). `content` holds the type's fields. See dzq.types."""
        from .statement import sign
        return sign(self, type, to, content, when=when, attachment=attachment, private=private)

    def __repr__(self):
        return "Identity(%s)" % self.aid


def blake3_said_registry(prefix):
    from .cesr import blake3_said
    return blake3_said("registry|" + prefix)

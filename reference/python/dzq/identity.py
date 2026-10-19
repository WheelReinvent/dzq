"""A minimal signer: enough to create, sign and hand over a gratitude.

    from dzq import Identity
    me = Identity.create()
    file_bytes = me.thank(to=friend_aid, title="Thank you", message="…")

Keys come from one 32-byte secret. Keep `secret_hex` private; with it,
`Identity.from_secret` recreates the same identifier. This is a reference
tool, not a wallet: it keeps no history across key rotations.
"""

import datetime
import os

from . import archive, build
from .blake3 import blake3, derive_key


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

    def thank(self, to, title, message, category="thanks", attachment=None, when=None):
        """A signed gratitude as .dzq bytes.

        `to` is an AID, or a condition such as "any(<AID>,<AID>)".
        `attachment` is an optional (filename, bytes, media type).
        """
        attrs = {"dt": (when or datetime.datetime.now(datetime.timezone.utc)).isoformat(timespec="seconds"),
                 "title": title, "message": message, "category": category}
        cond = to.startswith(("any(", "all(")) or ":" in to
        attrs["dq" if cond else "i"] = to
        asset = None
        if attachment is not None:
            name, body, mime = attachment
            attrs["attachment"] = {"d": blake3(body).hex(), "filename": name, "mime_type": mime, "size": len(body)}
            asset = (name, body)
        credential = self.gratitude(attrs)
        return archive.make_dzq(self.bundle(credential), attachment=asset)

"""A signed statement: create, sign, write, open, read, verify.

    import dzq
    alice, bob = dzq.Identity.create(), dzq.Identity.create()
    st = alice.sign(type="gratitude", to=bob.aid,
                    content={"title": "Thank you", "message": "…", "category": "help"})
    data = st.to_dzq()            # bytes of a .dzq file
    got = dzq.open(data)          # what the file says (not yet trusted)
    print(got.verify())           # whether to believe it
"""

import json

from . import acdc, archive, verify
from . import types as types_
from .blake3 import blake3


def _short(aid):
    return aid if not aid or len(aid) <= 16 else aid[:8] + "…" + aid[-4:]


class Statement:
    """What a statement says. Opening one checks nothing; call verify()."""

    def __init__(self, bundle, attachment=None):
        self.bundle = bundle
        self.raw = verify.split_bundle(bundle)[0]
        self.credential = json.loads(self.raw)
        self._attachment = attachment

    # --- what it says --------------------------------------------------

    @property
    def type(self):
        t = types_.by_schema(self.credential.get("s"))
        return t.name if t else "unknown (%s)" % self.credential.get("s")

    @property
    def issuer(self):
        return self.credential.get("i")

    @property
    def recipient(self):
        a = self.credential.get("a", {})
        return a.get("i") or a.get("dq")

    @property
    def date(self):
        return self.credential.get("a", {}).get("dt")

    @property
    def said(self):
        return self.credential.get("d")

    @property
    def content(self):
        """The type's own fields (title, message, …), without the envelope."""
        a = self.credential.get("a", {})
        return {k: v for k, v in a.items() if k not in ("d", "i", "dq", "dt")}

    def __repr__(self):
        lines = ["Statement (%s)" % self.type,
                 "  from     %s" % self.issuer,
                 "  to       %s" % self.recipient,
                 "  date     %s" % self.date]
        for k, v in self.content.items():
            if k == "attachment":
                v = "%s (%s, %d bytes)" % (v["filename"], v["mime_type"], v["size"])
            lines.append("  %-8s %s" % (k, v))
        lines.append("  id       %s" % self.said)
        return "\n".join(lines)

    # --- the file -------------------------------------------------------

    def to_dzq(self):
        """The .dzq file (bytes): ZIP with credential.acdc and the attachment, if any."""
        return archive.make_dzq(self.bundle, attachment=self._attachment)

    # --- trust ----------------------------------------------------------

    def verify(self, seal=None, kel=None):
        """Checks signature, content and the issuer's key history (SPEC §6)."""
        r = verify.check_credential(self.bundle, seal=seal, kel_text=kel)
        if r.valid and self._attachment is not None and "attachment" in self.content:
            named = self.content["attachment"]
            r["attachment"] = "ok" if blake3(self._attachment[1]).hex() == named["d"] else "mismatch"
        return Verification(r)


class Verification:
    """The answer to "can I believe this statement?"."""

    REASONS = {
        "format": "this is not a dzq statement",
        "canonical": "the bytes are not in canonical form",
        "schema": "unknown type, or fields that the type does not allow",
        "said": "the content was changed after it was signed",
        "kel": "the signer's key history is missing or invalid",
        "no-signature": "it is not signed",
        "signature": "the signature does not match the signer's keys",
        "not-current": "signed by a key the signer no longer uses, and never sealed",
        "seal": "the seal supplied does not prove it",
    }

    def __init__(self, result):
        self.result = result
        self.valid = bool(result.get("valid"))
        self.code = result.get("code")
        self.signed_by = result.get("issuer") if self.valid else None
        self.to = result.get("recipient") if self.valid else None
        self.sealed = bool(result.get("sealed"))

    def __bool__(self):
        return self.valid

    def __repr__(self):
        r = self.result
        if not self.valid:
            return "✗ NOT VALID: %s\n  (%s: %s)" % (self.REASONS.get(self.code, self.code), self.code, r.get("reason"))
        lines = ["✓ VALID",
                 "  signed by  %s" % r["issuer"],
                 "  to         %s" % r["recipient"],
                 "  unchanged  yes, every byte as signed"]
        if r.get("sealed"):
            lines.append("  final      yes: sealed in the signer's key history (event %s)" % r["anchored_at_sn"])
        else:
            lines.append("  final      not yet: valid as of the signer's key history in hand (event %s)"
                         % r.get("issuer_kel_sn"))
        if r.get("redeemed_at_sn") is not None:
            lines.append("  redeemed   at event %s" % r["redeemed_at_sn"])
        if r.get("attachment"):
            lines.append("  attachment %s" % r["attachment"])
        return "\n".join(lines)


def open_statement(data):
    """Reads a .dzq file (bytes) or a credential bundle (text). Trusts nothing yet."""
    if isinstance(data, (bytes, bytearray)) and data[:2] == b"PK":
        bundle, z = archive.open_dzq(bytes(data))
        st = Statement(bundle)
        att = st.content.get("attachment")
        if att:
            try:
                st._attachment = (att["filename"], archive._read(z, "assets/" + att["filename"]))
            except KeyError:
                pass
        return st
    if isinstance(data, (bytes, bytearray)):
        data = bytes(data).decode("utf-8")
    return Statement(data)


def sign(identity, type, to, content, when=None, attachment=None):
    """Builds and signs a statement of `type` from `identity` to `to`
    (an AID, or a condition like "any(<AID>,<AID>)")."""
    import datetime

    t = types_.by_name(type)
    content = dict(content)
    missing = [f for f in t.required if f not in content]
    unknown = [f for f in content if f not in t.fields]
    if missing or unknown:
        raise ValueError("%s needs %s%s" % (t.name, ", ".join(t.required),
                                            "; not allowed: " + ", ".join(unknown) if unknown else ""))
    asset = None
    if attachment is not None:
        name, body, mime = attachment
        content["attachment"] = {"d": blake3(body).hex(), "filename": name, "mime_type": mime, "size": len(body)}
        asset = (name, body)
    when = when or datetime.datetime.now(datetime.timezone.utc)
    attrs = {"dt": when.isoformat(timespec="seconds") if hasattr(when, "isoformat") else when}
    to_condition = to.startswith(("any(", "all(")) or ":" in to
    attrs["dq" if to_condition else "i"] = to
    for f in t.fields:
        if f in content:
            attrs[f] = content[f]
    schema = t.schema_to_condition if to_condition else t.schema_to_aid
    credential = acdc.saidify({"v": "", "d": "", "i": identity.prefix,
                               "ri": identity.registry, "s": schema, "a": dict({"d": ""}, **attrs)})
    return Statement(identity.bundle(credential), attachment=asset)

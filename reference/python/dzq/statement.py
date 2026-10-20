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

    def __init__(self, bundle, attachment=None, types=None):
        self.bundle = bundle
        self.raw = verify.split_bundle(bundle)[0]
        self.credential = json.loads(self.raw)
        self._attachment = attachment
        self.types = dict(types or {})   # {SAID: TypeDoc} beyond the built-in ones

    # --- what it says --------------------------------------------------

    @property
    def type_doc(self):
        """The TypeDoc of this statement's type, if this reader has it."""
        return types_.by_schema(self.credential.get("s"), self.types)

    @property
    def type(self):
        """The type's name (e.g. "dzq:gratitude"), or None when unknown here."""
        return acdc.type_of(self.credential.get("s"), self.types)

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
    def private(self):
        """Has a private content block (dzq/1.1)."""
        return "c" in self.credential.get("a", {})

    @property
    def hidden(self):
        """The private content is not in this copy (compact form)."""
        return isinstance(self.credential.get("a", {}).get("c"), str)

    @property
    def content(self):
        """The type's own fields (title, message, …), without the envelope.
        Private fields are missing when the copy is compact."""
        a = self.credential.get("a", {})
        out = {k: v for k, v in a.items() if k not in ("d", "i", "dq", "dt", "c")}
        c = a.get("c")
        if isinstance(c, dict):
            out.update({k: v for k, v in c.items() if k not in ("d", "u")})
        return out

    def compact(self):
        """The same statement with the private content replaced by its digest:
        what you show to a door. Same id, same signature."""
        if not self.private or self.hidden:
            return self
        compact_raw = acdc.dumps(acdc.compact(self.credential))
        return Statement(compact_raw + self.bundle[len(self.raw):], types=self.types)

    @property
    def re(self):
        """SAID of the statement this one answers, if it says (and shows)."""
        c = self.credential.get("a", {}).get("c")
        return c.get("re") if isinstance(c, dict) else None

    def __repr__(self):
        name = self.type or "type unknown here: %s" % self.credential.get("s")
        lines = ["Statement (%s)" % name,
                 "  from     %s" % self.issuer,
                 "  to       %s" % self.recipient,
                 "  date     %s" % self.date]
        for k, v in self.content.items():
            if archive._is_attachment(v):
                v = "%s (%s, %d bytes)" % (v["filename"], v["mime_type"], v["size"])
            elif not isinstance(v, str):
                v = json.dumps(v, ensure_ascii=False)
            lines.append("  %-8s %s" % (k, v))
        if self.hidden:
            lines.append("  private  hidden (only its digest is here: %s)" % self.credential["a"]["c"])
        lines.append("  id       %s" % self.said)
        return "\n".join(lines)

    # --- the file -------------------------------------------------------

    def to_dzq(self, carry_type=None):
        """The .dzq file (bytes): ZIP with credential.acdc, the attachment, if
        any, and — for a type that is not built in — its type document, so
        any reader can check the fields (carry_type=False to leave it out)."""
        doc = self.type_doc
        if carry_type is None:
            carry_type = doc is not None and doc.said not in types_.BUILTIN
        return archive.make_dzq(self.bundle, attachment=self._attachment,
                                type_doc=doc if carry_type and doc is not None else None)

    # --- trust ----------------------------------------------------------

    def verify(self, seal=None, kel=None):
        """Checks signature, content and the issuer's key history (SPEC §6)."""
        r = verify.check_credential(self.bundle, seal=seal, kel_text=kel, known=self.types)
        if r.valid and self._attachment is not None and isinstance(self.content.get("attachment"), dict):
            named = self.content["attachment"]
            r["attachment"] = "ok" if blake3(self._attachment[1]).hex() == named["d"] else "mismatch"
        return Verification(r)


class Verification:
    """The answer to "can I believe this statement?"."""

    REASONS = {
        "format": "this is not a dzq statement",
        "canonical": "the bytes are not in canonical form",
        "schema": "the envelope is malformed, or the fields break the type's rules",
        "said": "the content was changed after it was signed",
        "kel": "the signer's key history is missing or invalid",
        "no-signature": "it is not signed",
        "signature": "the signature does not match the signer's keys",
        "not-current": "signed by a key the signer no longer uses, and never sealed",
        "seal": "the seal supplied does not prove it",
        "archive": "the file is not a safe .dzq archive",
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
                 "  type       %s" % (r.get("type") if r.get("type_known")
                                      else "unknown to this reader — signature and envelope checked, fields not"),
                 "  signed by  %s" % r["issuer"],
                 "  to         %s" % r["recipient"],
                 "  unchanged  yes, every byte as signed"]
        if r.get("content") == "hidden":
            lines.append("  content    hidden: the signature covers it, but this copy does not show it")
        elif r.get("content") == "shown":
            lines.append("  content    shown, and it is exactly what was signed")
        if r.get("sealed"):
            lines.append("  final      yes: sealed in the signer's key history (event %s)" % r["anchored_at_sn"])
        else:
            lines.append("  final      not yet: valid as of the signer's key history in hand (event %s)"
                         % r.get("issuer_kel_sn"))
        if r.get("redeemed_at_sn") is not None:
            lines.append("  redeemed   at event %s" % r["redeemed_at_sn"])
        if r.get("re"):
            lines.append("  answers    %s" % r["re"])
        if r.get("look"):
            lines.append("  look       %s" % r["look"])
        if r.get("attachment"):
            lines.append("  attachment %s" % r["attachment"])
        return "\n".join(lines)


def open_statement(data, types=None):
    """Reads a .dzq file (bytes) or a statement bundle (text). Trusts nothing
    yet. `types`: {SAID: TypeDoc} this reader knows beyond the built-in
    ones; a type document carried in the file is used too."""
    known = dict(types or {})
    if isinstance(data, (bytes, bytearray)) and data[:2] == b"PK":
        bundle, z = archive.open_dzq(bytes(data))
        carried = archive.carried_types(z)
        carried.update(known)
        st = Statement(bundle, types=carried)
        att = archive.named_attachment(st.credential)
        if att is not None:
            try:
                st._attachment = (att["filename"], archive._read(z, "assets/" + att["filename"]))
            except KeyError:
                pass
        return st
    if isinstance(data, (bytes, bytearray)):
        data = bytes(data).decode("utf-8")
    return Statement(data, types=known)


def _is_condition(to):
    return to.startswith(("any(", "all(")) or ":" in to


def sign(identity, type, to, content, when=None, attachment=None, private=True, types=None, re=None):
    """Builds and signs a statement of `type` from `identity` to `to`
    (an AID, or a condition like "any(<AID>,<AID>)").

    `type` is a TypeDoc, a type SAID, or a name ("gratitude",
    "acme:board-post") among the built-in types and `types`. `content` holds
    the type's fields; `look` ("<source>:<id>") and `re` (the SAID of the
    statement this one answers) may be among them. Private fields go into a
    salted block that can be hidden later.

    private=False writes the dzq/1.0 layout, every field public forever
    (gratitude only, kept for old readers)."""
    import datetime
    import os

    from .cesr import encode
    from .typedoc import TypeDoc

    known = dict(types or {})
    doc = type if isinstance(type, TypeDoc) else types_.find(type, known)
    known[doc.said] = doc
    content = dict(content)
    if re is not None:
        content["re"] = re
    allowed = {f["name"] for f in doc.public + doc.private} | {"look", "re"}
    required = [f["name"] for f in doc.public + doc.private if f.get("required")]
    attach_fields = [f["name"] for f in doc.public + doc.private if f.get("kind") == "attachment"]
    missing = [f for f in required if f not in content and not (attachment is not None and f in attach_fields)]
    unknown = [f for f in content if f not in allowed]
    if missing or unknown:
        raise ValueError("%s needs %s%s" % (doc.name, ", ".join(required) or "nothing",
                                            "; not allowed: " + ", ".join(unknown) if unknown else ""))
    asset = None
    if attachment is not None:
        if not attach_fields:
            raise ValueError("%s takes no attachment" % doc.name)
        name, body, mime = attachment
        content[attach_fields[0]] = {"d": blake3(body).hex(), "filename": name, "mime_type": mime, "size": len(body)}
        asset = (name, body)
    when = when or datetime.datetime.now(datetime.timezone.utc)
    attrs = {"dt": when.isoformat(timespec="seconds") if hasattr(when, "isoformat") else when}
    attrs["dq" if _is_condition(to) else "i"] = to
    attrs.update(content)
    if private:
        try:
            credential = acdc.new_typed(identity.prefix, identity.registry, doc, attrs,
                                        salt=encode("0A", os.urandom(16)))
        except acdc.AcdcError as e:
            raise ValueError(str(e)) from e
    else:
        if doc.said != types_.GRATITUDE.said or "look" in content or "re" in content:
            raise ValueError("only a plain gratitude can be signed all-public (dzq/1.0)")
        schema = acdc.SCHEMA_GRATITUDE_CONDITION if _is_condition(to) else acdc.SCHEMA_GRATITUDE
        credential = acdc.saidify({"v": "", "d": "", "i": identity.prefix,
                                   "ri": identity.registry, "s": schema, "a": dict({"d": ""}, **attrs)})
    return Statement(identity.bundle(credential), attachment=asset, types=known)

"""Gratitude ACDCs: canonical form, SAIDs, schemas (dzq/1.0 §3)."""

import json

from .cesr import SAID_PLACEHOLDER, blake3_said

ACDC_PREFIX = "ACDC10JSON"

# SAIDs fixed by the specification (schemas/index.json). A verifier compares
# `s` with these; it never has to fetch a schema.
SCHEMA_GRATITUDE = "EHJJvD_pHa1kHRWiQq9o1KxNHNpnFpArKmGGltmDjTav"            # 1.0.0, to one AID
SCHEMA_GRATITUDE_CONDITION = "EL3ntXZJeGkmy1w43X19vtv9J5dGTiHjqwxpEKtZRSMZ"  # 2.0.0, to a condition
SCHEMA_BINDING = "ED-ubFgDExNNMYg9Q_Y_VmvJorQpAXGbGX8x8urN7EVo"
# dzq/1.1: private content (title, message, attachment in a salted block `a.c`).
SCHEMA_GRATITUDE_PRIVATE = "EMI0LpKv73h125n5PgJIYxXc1u3QBvkvWbt3hl9FvKn_"            # 1.1.0, to one AID
SCHEMA_GRATITUDE_PRIVATE_CONDITION = "EMa9OBQr5dKKmPH2hLNViB8QVEN1m6GVlVJq2Tvsildc"  # 2.1.0, to a condition

# dzq/1.2: gratitude with `look`; certificates.
SCHEMA_GRATITUDE_12 = "EAvj2DtbSBE_wWHrl2bv6kSmD6GaYOaStMcDraAjXK81"            # 1.2.0, to one AID
SCHEMA_GRATITUDE_12_CONDITION = "EJunsC_WSH8aI_5wu9tYHyETyiO-I8FcS-vOFeH50G1V"  # 2.2.0, to a condition
SCHEMA_CERTIFICATE = "EP1v8jIBloNuOHRz9j3BlFwpHkI_iGLkyC6UJAwjt-Yk"             # 1.1.0, to one AID
SCHEMA_CERTIFICATE_CONDITION = "EEO24n7vWuRj5pYYVJGCSg1tYqz267qHGrE-Q5oYUk2j"   # 2.1.0, to a condition
SCHEMA_LOOK = "EIPQeKyOu9UNczhgujDJwHEYA1SP1CuKen9pRt8PxZfv"                    # look/1 document


class Layout:
    """A private-content schema: its type, recipient field, public fields
    (after `dt`) and content-block fields (after `d`, `u`), in order.
    Each field: (name, required, max length or None, kind)."""

    def __init__(self, type, to, public, content):
        self.type, self.to, self.public, self.content = type, to, public, content


_GRAT_PUBLIC = [("category", True, 64, "text")]
_GRAT_11 = [("title", True, 200, "text"), ("message", True, 5000, "text"), ("attachment", False, None, "attachment")]
_GRAT_12 = _GRAT_11 + [("look", False, None, "look")]
_CERT_PUBLIC = [("until", False, None, "text")]
_CERT = [("what", True, 200, "text"), ("note", False, 5000, "text"), ("look", False, None, "look")]

LAYOUTS = {
    SCHEMA_GRATITUDE_PRIVATE: Layout("gratitude", "i", _GRAT_PUBLIC, _GRAT_11),
    SCHEMA_GRATITUDE_PRIVATE_CONDITION: Layout("gratitude", "dq", _GRAT_PUBLIC, _GRAT_11),
    SCHEMA_GRATITUDE_12: Layout("gratitude", "i", _GRAT_PUBLIC, _GRAT_12),
    SCHEMA_GRATITUDE_12_CONDITION: Layout("gratitude", "dq", _GRAT_PUBLIC, _GRAT_12),
    SCHEMA_CERTIFICATE: Layout("certificate", "i", _CERT_PUBLIC, _CERT),
    SCHEMA_CERTIFICATE_CONDITION: Layout("certificate", "dq", _CERT_PUBLIC, _CERT),
}

TO_AID = (SCHEMA_GRATITUDE,) + tuple(k for k, l in LAYOUTS.items() if l.to == "i")
TO_CONDITION = (SCHEMA_GRATITUDE_CONDITION,) + tuple(k for k, l in LAYOUTS.items() if l.to == "dq")
PRIVATE = tuple(LAYOUTS)
GRATITUDE_SCHEMAS = (SCHEMA_GRATITUDE, SCHEMA_GRATITUDE_CONDITION) + tuple(
    k for k, l in LAYOUTS.items() if l.type == "gratitude")
CERTIFICATE_SCHEMAS = tuple(k for k, l in LAYOUTS.items() if l.type == "certificate")

import re as _re  # noqa: E402
LOOK_RE = _re.compile(r"[a-z0-9-]+:\S+")


def type_of(schema):
    if schema in (SCHEMA_GRATITUDE, SCHEMA_GRATITUDE_CONDITION):
        return "gratitude"
    layout = LAYOUTS.get(schema)
    return layout.type if layout else None


class AcdcError(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def dumps(value):
    """Compact JSON exactly as the canonical form requires (UTF-8, no spaces,
    non-ASCII characters unescaped)."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def version_string(size):
    return "%s%06x_" % (ACDC_PREFIX, size)


def parse_version_size(v):
    if not isinstance(v, str) or not v.startswith(ACDC_PREFIX) or len(v) != 17 or not v.endswith("_"):
        return None
    try:
        return int(v[10:16], 16)
    except ValueError:
        return None


ATTACHMENT_FIELDS = ("d", "filename", "mime_type", "size")


def _attachment(att, where):
    if not isinstance(att, dict) or set(att) != set(ATTACHMENT_FIELDS):
        raise AcdcError("schema", "%s.attachment must have exactly d, filename, mime_type, size" % where)
    if not isinstance(att["size"], int) or isinstance(att["size"], bool) or att["size"] < 0:
        raise AcdcError("schema", "%s.attachment.size must be a non-negative integer" % where)
    for k in ("d", "filename", "mime_type"):
        if not isinstance(att[k], str):
            raise AcdcError("schema", "%s.attachment.%s must be a string" % (where, k))
    return {k: att[k] for k in ATTACHMENT_FIELDS}


def _salt_ok(u):
    from .cesr import CesrError, decode
    if not isinstance(u, str) or not u.startswith("0A"):
        return False
    try:
        return len(decode(u, 2, 24)) == 16
    except CesrError:
        return False


def _field(where, name, value, max_len, kind):
    if kind == "attachment":
        return _attachment(value, where)
    if not isinstance(value, str):
        raise AcdcError("schema", "%s.%s must be a string" % (where, name))
    if max_len is not None and len(value) > max_len:
        raise AcdcError("schema", "a text field is too long")
    if kind == "look" and not LOOK_RE.fullmatch(value):
        raise AcdcError("schema", "%s.look must be <source>:<id>" % where)
    return value


def _content(c, layout):
    """The private content block (expanded form) in canonical order."""
    if not isinstance(c, dict):
        raise AcdcError("schema", "a.c must be a SAID or the content block")
    allowed = {"d", "u"} | {f[0] for f in layout.content}
    extra = set(c) - allowed
    if extra:
        raise AcdcError("schema", "unknown content field(s): %s" % ", ".join(sorted(extra)))
    for k in ("d", "u"):
        if not isinstance(c.get(k), str):
            raise AcdcError("schema", "a.c.%s is required and must be a string" % k)
    if not _salt_ok(c["u"]):
        raise AcdcError("schema", "a.c.u must be a 128-bit salt (CESR 0A…)")
    out = {"d": c["d"], "u": c["u"]}
    for name, required, max_len, kind in layout.content:
        if name in c:
            out[name] = _field("a.c", name, c[name], max_len, kind)
        elif required:
            raise AcdcError("schema", "a.c.%s is required" % name)
    return out


def _private_attributes(a, layout):
    allowed = {"d", layout.to, "dt", "c"} | {f[0] for f in layout.public}
    extra = set(a) - allowed
    if extra:
        raise AcdcError("schema", "unknown attribute(s): %s" % ", ".join(sorted(extra)))
    out = {}
    for k in ("d", layout.to, "dt"):
        if not isinstance(a.get(k), str):
            raise AcdcError("schema", "a.%s is required and must be a string" % k)
        out[k] = a[k]
    for name, required, max_len, kind in layout.public:
        if name in a:
            out[name] = _field("a", name, a[name], max_len, kind)
        elif required:
            raise AcdcError("schema", "missing a.%s" % name)
    if "c" not in a:
        raise AcdcError("schema", "missing a.c")
    out["c"] = a["c"] if isinstance(a["c"], str) else _content(a["c"], layout)
    return out


def content_said(c):
    tmp = dict(c)
    tmp["d"] = SAID_PLACEHOLDER
    return blake3_said(dumps(tmp))


def compact(acdc):
    """The compact form: the content block replaced by its SAID."""
    out = dict(acdc)
    if isinstance(acdc.get("a", {}).get("c"), dict):
        out["a"] = dict(acdc["a"], c=acdc["a"]["c"]["d"])
    return out


def _attributes(a, layout=None):
    """The attribute block in canonical field order. Rejects unknown fields."""
    if not isinstance(a, dict):
        raise AcdcError("schema", "a must be an object")
    if layout is not None:
        return _private_attributes(a, layout)
    allowed = {"d", "i", "dq", "dt", "title", "message", "category", "attachment"}
    extra = set(a) - allowed
    if extra:
        raise AcdcError("schema", "unknown attribute(s): %s" % ", ".join(sorted(extra)))
    out = {}
    for k in ("d", "i", "dq", "dt", "title", "message", "category"):
        if k in a:
            if not isinstance(a[k], str):
                raise AcdcError("schema", "a.%s must be a string" % k)
            out[k] = a[k]
        elif k not in ("i", "dq"):
            raise AcdcError("schema", "missing a.%s" % k)
    if "attachment" in a:
        out["attachment"] = _attachment(a["attachment"], "a")
    if len(out["title"]) > 200 or len(out["message"]) > 5000 or len(out["category"]) > 64:
        raise AcdcError("schema", "a text field is too long")
    return out


def _top(acdc):
    if not isinstance(acdc, dict):
        raise AcdcError("schema", "not a JSON object")
    fields = ("v", "d", "i", "ri", "s", "a")
    if set(acdc) != set(fields):
        raise AcdcError("schema", "a gratitude has exactly the fields v, d, i, ri, s, a")
    for k in fields[:-1]:
        if not isinstance(acdc[k], str):
            raise AcdcError("schema", "%s must be a string" % k)
    return {"v": acdc["v"], "d": acdc["d"], "i": acdc["i"], "ri": acdc["ri"], "s": acdc["s"],
            "a": _attributes(acdc["a"], LAYOUTS.get(acdc["s"]))}


def attribute_said(a):
    tmp = dict(a)
    tmp["d"] = SAID_PLACEHOLDER
    return blake3_said(dumps(tmp))


def saidify(acdc):
    """Fills c.d (private content), a.d, v and d of a gratitude. All over the
    compact form. Returns the full form (content expanded, if any)."""
    acdc = _top(acdc)
    if isinstance(acdc["a"].get("c"), dict):
        acdc["a"]["c"]["d"] = content_said(acdc["a"]["c"])
    full_c = acdc["a"].get("c")
    acdc = compact(acdc)
    acdc["a"]["d"] = attribute_said(acdc["a"])
    acdc["d"] = SAID_PLACEHOLDER
    acdc["v"] = version_string(0)
    acdc["v"] = version_string(len(dumps(acdc).encode("utf-8")))
    acdc["d"] = blake3_said(dumps(acdc))
    if isinstance(full_c, dict):
        acdc["a"] = dict(acdc["a"], c=full_c)
    return acdc


def new_gratitude(issuer, registry, attributes):
    """Builds a gratitude. `attributes` has i (an AID) or dq (a condition)."""
    a = {"d": ""}
    for k in ("i", "dq", "dt", "title", "message", "category", "attachment"):
        if k in attributes:
            a[k] = attributes[k]
    schema = SCHEMA_GRATITUDE_CONDITION if "dq" in a else SCHEMA_GRATITUDE
    return saidify({"v": "", "d": "", "i": issuer, "ri": registry, "s": schema, "a": a})


def new_statement(issuer, registry, schema, attributes, salt):
    """A private-content statement of any layout: envelope (i or dq, dt),
    the layout's public fields, and its content fields in a salted block."""
    layout = LAYOUTS[schema]
    a = {"d": "", layout.to: attributes[layout.to], "dt": attributes["dt"]}
    for name, _, _, _ in layout.public:
        if name in attributes:
            a[name] = attributes[name]
    c = {"d": "", "u": salt}
    for name, _, _, _ in layout.content:
        if name in attributes:
            c[name] = attributes[name]
    a["c"] = c
    return saidify({"v": "", "d": "", "i": issuer, "ri": registry, "s": schema, "a": a})


def new_private_gratitude(issuer, registry, attributes, salt):
    """A dzq/1.1 gratitude (schema 1.1.0 / 2.1.0)."""
    schema = SCHEMA_GRATITUDE_PRIVATE_CONDITION if "dq" in attributes else SCHEMA_GRATITUDE_PRIVATE
    return new_statement(issuer, registry, schema, attributes, salt)


class Integrity:
    def __init__(self, said, issuer, recipient, schema, acdc, signed_raw, content):
        self.said, self.issuer, self.recipient, self.schema, self.acdc = said, issuer, recipient, schema, acdc
        self.signed_raw = signed_raw   # the bytes the signature covers (the compact form)
        self.content = content         # the disclosed private block, or None


def check_integrity(raw):
    """Checks that `raw` (str) is a canonical gratitude whose SAIDs recompute."""
    if not raw.startswith('{"v":'):
        raise AcdcError("canonical", "ACDC is not in canonical form (or is a pre-dzq/1.0 legacy credential)")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        raise AcdcError("format", "invalid JSON: %s" % e) from e
    acdc = _top(parsed)
    if dumps(acdc) != raw:
        raise AcdcError("canonical", "ACDC is not in canonical form")
    a = acdc["a"]
    if acdc["s"] in TO_AID:
        if "i" not in a or "dq" in a:
            raise AcdcError("schema", "a gratitude to one AID names its recipient in a.i")
        recipient = a["i"]
    elif acdc["s"] in TO_CONDITION:
        if "dq" not in a or "i" in a:
            raise AcdcError("schema", "a gratitude to a condition has a.dq and no a.i")
        recipient = a["dq"]
    else:
        raise AcdcError("schema", "unknown schema %s" % acdc["s"])
    content = None
    if isinstance(a.get("c"), dict):
        # Expanded: the block must be the one whose SAID the signed form holds.
        content = a["c"]
        if content_said(content) != content["d"]:
            raise AcdcError("said", "content block SAID does not match its content")
    signed = compact(acdc)
    signed_raw = dumps(signed)
    if attribute_said(signed["a"]) != a["d"]:
        raise AcdcError("said", "attribute block SAID does not match")
    if acdc["v"] != version_string(len(signed_raw.encode("utf-8"))):
        raise AcdcError("said", "version string size does not match")
    tmp = dict(signed)
    tmp["d"] = SAID_PLACEHOLDER
    if blake3_said(dumps(tmp)) != acdc["d"]:
        raise AcdcError("said", "credential SAID does not match its content")
    return Integrity(acdc["d"], acdc["i"], recipient, acdc["s"], acdc, signed_raw, content)


def close_said(statement_said):
    """Digest an issuer anchors to close a certificate early (certificates)."""
    return blake3_said(dumps({"d": SAID_PLACEHOLDER, "t": "close", "g": statement_said}))


def redemption_said(gratitude_said):
    """Digest an issuer anchors to redeem a gratitude (extension: redemption)."""
    return blake3_said(dumps({"d": SAID_PLACEHOLDER, "t": "redeem", "g": gratitude_said}))

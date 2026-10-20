"""Statements: canonical form, SAIDs, the envelope, base and open types (SPEC §3, §8)."""

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

# dzq/1.2: open types. New statements use type documents (typedoc.py);
# the base types (types.py) are type documents too.
SCHEMA_GRATITUDE_12 = "EDM7gu9-qtygix9Ukwfo_iE9n4EGy8mU3KmMABB7hjhG"   # dzq:gratitude 1.2.0
SCHEMA_LOOK = "EIPQeKyOu9UNczhgujDJwHEYA1SP1CuKen9pRt8PxZfv"          # look/1 document (optional extension)

MAX_ACDC = 256 * 1024


class Layout:
    """A dzq/1.1 private-content schema (before type documents)."""

    def __init__(self, type, to, public, content):
        self.type, self.to, self.public, self.content = type, to, public, content


_GRAT_PUBLIC = [("category", True, 64, "text")]
_GRAT_11 = [("title", True, 200, "text"), ("message", True, 5000, "text"), ("attachment", False, None, "attachment")]

LAYOUTS = {
    SCHEMA_GRATITUDE_PRIVATE: Layout("dzq:gratitude", "i", _GRAT_PUBLIC, _GRAT_11),
    SCHEMA_GRATITUDE_PRIVATE_CONDITION: Layout("dzq:gratitude", "dq", _GRAT_PUBLIC, _GRAT_11),
}
LEGACY_PUBLIC = (SCHEMA_GRATITUDE, SCHEMA_GRATITUDE_CONDITION)

import re as _re  # noqa: E402
LOOK_RE = _re.compile(r"[a-z0-9-]+:\S+")
SAID_RE = _re.compile(r"E[A-Za-z0-9_-]{43}")
NAME_RE = _re.compile(r"[a-z][a-z0-9_]{0,31}")


def builtin_types():
    from . import types as types_
    return types_.BUILTIN


def type_of(schema, known=None):
    """The type name for a schema SAID, if this reader knows it."""
    if schema in LEGACY_PUBLIC:
        return "dzq:gratitude"
    if schema in LAYOUTS:
        return LAYOUTS[schema].type
    doc = (known or {}).get(schema) or builtin_types().get(schema)
    return doc.name if doc else None


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
    return value


# --- open types (dzq/1.2) ----------------------------------------------------

def _plain(value, where, depth=0):
    """Generic values: strings, integers, booleans, lists and objects of
    them. No floats (two spellings, one number) and no null."""
    if depth > 8:
        raise AcdcError("schema", "%s: nested too deep" % where)
    if isinstance(value, bool) or isinstance(value, str):
        return
    if isinstance(value, int):
        if abs(value) > 2 ** 53:
            raise AcdcError("schema", "%s: integers beyond 2^53 are not allowed" % where)
        return
    if isinstance(value, list):
        for v in value:
            _plain(v, where, depth + 1)
        return
    if isinstance(value, dict):
        for k, v in value.items():
            _plain(v, where, depth + 1)
        return
    raise AcdcError("schema", "%s: only strings, integers, booleans, lists and objects" % where)


def _generic_attributes(a):
    """The envelope rules every type follows (SPEC §3.1, §8.5). Field order:
    `a` starts with d, i or dq, dt; `c` starts with d, u."""
    if not isinstance(a, dict):
        raise AcdcError("schema", "a must be an object")
    keys = list(a)
    if len(keys) < 3 or keys[0] != "d" or keys[1] not in ("i", "dq") or keys[2] != "dt":
        raise AcdcError("schema", "a starts with d, then i or dq, then dt")
    if "i" in a and "dq" in a:
        raise AcdcError("schema", "a statement has a.i or a.dq, not both")
    for k in ("d", keys[1], "dt"):
        if not isinstance(a[k], str):
            raise AcdcError("schema", "a.%s must be a string" % k)
    for k in keys[3:]:
        if k == "c":
            continue
        if not NAME_RE.fullmatch(k) or k in ("d", "i", "dq", "dt", "u", "look", "re"):
            raise AcdcError("schema", "a.%s is not an allowed field name" % k)
        _plain(a[k], "a.%s" % k)
    if "c" in a:
        if keys[-1] != "c":
            raise AcdcError("schema", "a.c comes last")
        c = a["c"]
        if isinstance(c, dict):
            ck = list(c)
            if len(ck) < 2 or ck[0] != "d" or ck[1] != "u":
                raise AcdcError("schema", "a.c starts with d, then u")
            if not isinstance(c["d"], str) or not _salt_ok(c["u"]):
                raise AcdcError("schema", "a.c.u must be a 128-bit salt (CESR 0A…)")
            for k in ck[2:]:
                if not NAME_RE.fullmatch(k) or k in ("d", "i", "dq", "dt", "u", "c"):
                    raise AcdcError("schema", "a.c.%s is not an allowed field name" % k)
                _plain(c[k], "a.c.%s" % k)
            if "look" in c and not (isinstance(c["look"], str) and LOOK_RE.fullmatch(c["look"])):
                raise AcdcError("schema", "a.c.look must be <source>:<id>")
            if "re" in c and not (isinstance(c["re"], str) and SAID_RE.fullmatch(c["re"])):
                raise AcdcError("schema", "a.c.re must be a SAID")
        elif not (isinstance(c, str) and SAID_RE.fullmatch(c)):
            raise AcdcError("schema", "a.c must be the private block or its SAID")
    return a


def _check_against(a, doc):
    """A statement of a known type: exactly its fields, with their limits."""
    to = "aid" if "i" in a else "condition"
    if to not in doc.to:
        raise AcdcError("schema", "%s is not addressed to a%s %s" % (doc.name, "n" if to == "aid" else "", to))

    def check(block, fields, where, extra_ok):
        names = {f["name"] for f in fields}
        unknown = [k for k in block if k not in names and k not in extra_ok]
        if unknown:
            raise AcdcError("schema", "unknown %s field(s) for %s: %s" % (where, doc.name, ", ".join(unknown)))
        for f in fields:
            if f["name"] not in block:
                if f.get("required"):
                    raise AcdcError("schema", "%s needs %s.%s" % (doc.name, where, f["name"]))
                continue
            _field(where, f["name"], block[f["name"]], f.get("max"), f.get("kind", "text"))

    check(a, doc.public, "a", {"d", "i", "dq", "dt", "c"})
    c = a.get("c")
    if doc.private and c is None:
        raise AcdcError("schema", "%s has private fields: a.c is required" % doc.name)
    if isinstance(c, dict):
        check(c, doc.private, "a.c", {"d", "u", "look", "re"})


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


def _top(acdc, known=None):
    if not isinstance(acdc, dict):
        raise AcdcError("schema", "not a JSON object")
    fields = ("v", "d", "i", "ri", "s", "a")
    if set(acdc) != set(fields):
        raise AcdcError("schema", "a statement has exactly the fields v, d, i, ri, s, a")
    for k in fields[:-1]:
        if not isinstance(acdc[k], str):
            raise AcdcError("schema", "%s must be a string" % k)
    s = acdc["s"]
    if s in LEGACY_PUBLIC or s in LAYOUTS:
        a = _attributes(acdc["a"], LAYOUTS.get(s))
    else:
        if not SAID_RE.fullmatch(s):
            raise AcdcError("schema", "s must be the SAID of a type document")
        a = _generic_attributes(acdc["a"])
        doc = (known or {}).get(s) or builtin_types().get(s)
        if doc is not None:
            _check_against(a, doc)
    return {"v": acdc["v"], "d": acdc["d"], "i": acdc["i"], "ri": acdc["ri"], "s": s, "a": a}


def attribute_said(a):
    tmp = dict(a)
    tmp["d"] = SAID_PLACEHOLDER
    return blake3_said(dumps(tmp))


def saidify(acdc, known=None):
    """Fills c.d (private content), a.d, v and d of a statement. All over the
    compact form. Returns the full form (content expanded, if any)."""
    acdc = _top(acdc, known)
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


def new_typed(issuer, registry, doc, attributes, salt):
    """A statement of a type document `doc`: envelope (i or dq, dt), the
    type's public fields, then its private fields plus look / re in a salted
    block — each in the order the type lists them."""
    to = "dq" if "dq" in attributes else "i"
    a = {"d": "", to: attributes[to], "dt": attributes["dt"]}
    for f in doc.public:
        if f["name"] in attributes:
            a[f["name"]] = attributes[f["name"]]
    c = {"d": "", "u": salt}
    for f in doc.private:
        if f["name"] in attributes:
            c[f["name"]] = attributes[f["name"]]
    for k in ("look", "re"):
        if k in attributes:
            c[k] = attributes[k]
    if len(c) > 2 or doc.private:
        a["c"] = c
    return saidify({"v": "", "d": "", "i": issuer, "ri": registry, "s": doc.said, "a": a}, {doc.said: doc})


def new_statement(issuer, registry, schema, attributes, salt):
    """A dzq/1.1 private-content gratitude (built-in layout)."""
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


def check_integrity(raw, known=None):
    """Checks that `raw` (str) is a canonical statement whose SAIDs recompute.
    `known` maps type SAID → TypeDoc for types beyond the base types."""
    if len(raw.encode("utf-8")) > MAX_ACDC:
        raise AcdcError("format", "statement larger than 256 KB")
    if not raw.startswith('{"v":'):
        raise AcdcError("canonical", "ACDC is not in canonical form (or is a pre-dzq/1.0 legacy credential)")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        raise AcdcError("format", "invalid JSON: %s" % e) from e
    acdc = _top(parsed, known)
    if dumps(acdc) != raw:
        raise AcdcError("canonical", "ACDC is not in canonical form")
    a = acdc["a"]
    s = acdc["s"]
    if s == SCHEMA_GRATITUDE or (s in LAYOUTS and LAYOUTS[s].to == "i"):
        if "i" not in a or "dq" in a:
            raise AcdcError("schema", "a gratitude to one AID names its recipient in a.i")
    elif s == SCHEMA_GRATITUDE_CONDITION or s in LAYOUTS:
        if "dq" not in a or "i" in a:
            raise AcdcError("schema", "a gratitude to a condition has a.dq and no a.i")
    recipient = a.get("i", a.get("dq"))
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


def to_aid(schema, a):
    """Is the statement addressed to one AID (a.i), not to a condition?"""
    return "i" in a


def redemption_said(gratitude_said):
    """Digest an issuer anchors to redeem a gratitude (extension: redemption)."""
    return blake3_said(dumps({"d": SAID_PLACEHOLDER, "t": "redeem", "g": gratitude_said}))

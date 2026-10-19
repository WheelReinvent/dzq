"""Gratitude ACDCs: canonical form, SAIDs, schemas (dzq/1.0 §3)."""

import json

from .cesr import SAID_PLACEHOLDER, blake3_said

ACDC_PREFIX = "ACDC10JSON"

# SAIDs fixed by the specification (schemas/index.json). A verifier compares
# `s` with these; it never has to fetch a schema.
SCHEMA_GRATITUDE = "EHJJvD_pHa1kHRWiQq9o1KxNHNpnFpArKmGGltmDjTav"            # 1.0.0, to one AID
SCHEMA_GRATITUDE_CONDITION = "EL3ntXZJeGkmy1w43X19vtv9J5dGTiHjqwxpEKtZRSMZ"  # 2.0.0, to a condition
SCHEMA_BINDING = "ED-ubFgDExNNMYg9Q_Y_VmvJorQpAXGbGX8x8urN7EVo"


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


def _attributes(a):
    """The attribute block in canonical field order. Rejects unknown fields."""
    if not isinstance(a, dict):
        raise AcdcError("schema", "a must be an object")
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
        att = a["attachment"]
        if not isinstance(att, dict) or set(att) != set(ATTACHMENT_FIELDS):
            raise AcdcError("schema", "a.attachment must have exactly d, filename, mime_type, size")
        if not isinstance(att["size"], int) or isinstance(att["size"], bool) or att["size"] < 0:
            raise AcdcError("schema", "a.attachment.size must be a non-negative integer")
        for k in ("d", "filename", "mime_type"):
            if not isinstance(att[k], str):
                raise AcdcError("schema", "a.attachment.%s must be a string" % k)
        out["attachment"] = {k: att[k] for k in ATTACHMENT_FIELDS}
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
            "a": _attributes(acdc["a"])}


def attribute_said(a):
    tmp = dict(a)
    tmp["d"] = SAID_PLACEHOLDER
    return blake3_said(dumps(tmp))


def saidify(acdc):
    """Fills a.d, v and d of a gratitude (dict in canonical order). Returns it."""
    acdc = _top(acdc)
    acdc["a"]["d"] = attribute_said(acdc["a"])
    acdc["d"] = SAID_PLACEHOLDER
    acdc["v"] = version_string(0)
    acdc["v"] = version_string(len(dumps(acdc).encode("utf-8")))
    acdc["d"] = blake3_said(dumps(acdc))
    return acdc


def new_gratitude(issuer, registry, attributes):
    """Builds a gratitude. `attributes` has i (an AID) or dq (a condition)."""
    a = {"d": ""}
    for k in ("i", "dq", "dt", "title", "message", "category", "attachment"):
        if k in attributes:
            a[k] = attributes[k]
    schema = SCHEMA_GRATITUDE_CONDITION if "dq" in a else SCHEMA_GRATITUDE
    return saidify({"v": "", "d": "", "i": issuer, "ri": registry, "s": schema, "a": a})


class Integrity:
    def __init__(self, said, issuer, recipient, schema, acdc):
        self.said, self.issuer, self.recipient, self.schema, self.acdc = said, issuer, recipient, schema, acdc


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
    if acdc["s"] == SCHEMA_GRATITUDE:
        if "i" not in a or "dq" in a:
            raise AcdcError("schema", "a gratitude under schema 1.0.0 names its recipient in a.i")
        recipient = a["i"]
    elif acdc["s"] == SCHEMA_GRATITUDE_CONDITION:
        if "dq" not in a or "i" in a:
            raise AcdcError("schema", "a gratitude to a condition has a.dq and no a.i")
        recipient = a["dq"]
    else:
        raise AcdcError("schema", "unknown schema %s" % acdc["s"])
    if attribute_said(a) != a["d"]:
        raise AcdcError("said", "attribute block SAID does not match")
    if parse_version_size(acdc["v"]) != len(raw.encode("utf-8")):
        raise AcdcError("said", "version string size does not match")
    tmp = dict(acdc)
    tmp["d"] = SAID_PLACEHOLDER
    if blake3_said(dumps(tmp)) != acdc["d"]:
        raise AcdcError("said", "credential SAID does not match its content")
    return Integrity(acdc["d"], acdc["i"], recipient, acdc["s"], acdc)


def redemption_said(gratitude_said):
    """Digest an issuer anchors to redeem a gratitude (extension: redemption)."""
    return blake3_said(dumps({"d": SAID_PLACEHOLDER, "t": "redeem", "g": gratitude_said}))

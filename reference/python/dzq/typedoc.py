"""Type documents: how anyone defines a statement type (SPEC §8).

A type document is a JSON Schema whose `$id` is its own SAID, with a `dzq`
block that lists the type's fields in a form any language can read without
a JSON Schema validator:

    "dzq": {"type": "acme:board-post", "version": "1.0.0", "to": ["aid", "condition"],
            "public":  [{"name": "category", "required": true, "max": 64}],
            "private": [{"name": "text", "required": true, "max": 2000},
                        {"name": "photo", "kind": "attachment"}]}

`make_type` builds one; `TypeDoc` reads one. The statement's `s` is the
type document's SAID.
"""

import json
import re

from .cesr import SAID_PLACEHOLDER, blake3_said

NAME_RE = re.compile(r"[a-z0-9-]+:[a-z0-9][a-z0-9.-]{0,63}")
FIELD_RE = re.compile(r"[a-z][a-z0-9_]{0,31}")
RESERVED = {"d", "i", "req", "dq", "dt", "c", "u", "look", "re", "from", "to", "since", "count"}
KINDS = ("text", "attachment")
DZQ_SOURCE = "dzq"


class TypeError_(ValueError):
    pass


def _dumps(v):
    return json.dumps(v, ensure_ascii=False, separators=(",", ":"))


def _field_schema(f):
    if f.get("kind", "text") == "attachment":
        return {"type": "object", "properties": {
            "d": {"type": "string", "description": "BLAKE3-256 hex digest of the file"},
            "filename": {"type": "string"}, "mime_type": {"type": "string"}, "size": {"type": "integer"}},
            "required": ["d", "filename", "mime_type", "size"], "additionalProperties": False}
    s = {"type": "string"}
    if f.get("max") is not None:
        s["maxLength"] = f["max"]
    if f.get("description"):
        s["description"] = f["description"]
    return s


def _check_fields(fields, where):
    seen = set()
    out = []
    for f in fields:
        if not isinstance(f, dict) or not isinstance(f.get("name"), str) or not FIELD_RE.fullmatch(f["name"]):
            raise TypeError_("%s: every field needs a name of [a-z][a-z0-9_]*" % where)
        if f["name"] in RESERVED:
            raise TypeError_("%s: %r is reserved" % (where, f["name"]))
        if f["name"] in seen:
            raise TypeError_("%s: %r twice" % (where, f["name"]))
        seen.add(f["name"])
        kind = f.get("kind", "text")
        if kind not in KINDS:
            raise TypeError_("%s: kind must be one of %s" % (where, ", ".join(KINDS)))
        mx = f.get("max")
        if mx is not None and (not isinstance(mx, int) or isinstance(mx, bool) or mx < 1):
            raise TypeError_("%s: max must be a positive integer" % where)
        g = {"name": f["name"]}
        if f.get("required"):
            g["required"] = True
        if kind != "text":
            g["kind"] = kind
        if mx is not None:
            g["max"] = mx
        if f.get("description"):
            g["description"] = str(f["description"])
        out.append(g)
    return out


def make_type(name, version, public=(), private=(), title=None, description="", to=("aid", "condition")):
    """Builds a type document. Returns (SAID, canonical JSON text)."""
    if not NAME_RE.fullmatch(name):
        raise TypeError_("a type name is <source>:<name>, lowercase")
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise TypeError_("version is MAJOR.MINOR.PATCH")
    to = list(to)
    if not to or any(t not in ("aid", "condition") for t in to):
        raise TypeError_("to is a non-empty subset of aid, condition")
    public = _check_fields(public, "public")
    private = _check_fields(private, "private")
    if set(f["name"] for f in public) & set(f["name"] for f in private):
        raise TypeError_("a field is either public or private")

    recipients = []
    if "aid" in to:
        recipients.append({"required": ["i"], "properties": {"i": {"type": "string", "description": "Recipient AID"}}})
    if "condition" in to:
        recipients.append({"required": ["req"], "properties": {"req": {
            "oneOf": [{"type": "string"}, {"type": "array", "items": {"type": "string"}, "minItems": 1}],
            "description": "A condition, or a list of conditions any of which is enough (SPEC §4)"}}})
    c_props = {"d": {"type": "string"}, "u": {"type": "string", "description": "Salt: 128 random bits, CESR 0A…"}}
    c_props.update({f["name"]: _field_schema(f) for f in private})
    c_props["look"] = {"type": "string", "description": "<source>:<id> of how it wants to be shown"}
    c_props["re"] = {"type": "string", "description": "SAID of the statement this one answers"}
    a_props = {"d": {"type": "string"}, "i": {"type": "string"},
               "req": {"oneOf": [{"type": "string"}, {"type": "array", "items": {"type": "string"}}]},
               "dt": {"type": "string", "format": "date-time"}}
    a_props.update({f["name"]: _field_schema(f) for f in public})
    a_props["c"] = {"oneOf": [{"type": "string", "description": "Compact form: SAID of the private block"},
                              {"type": "object", "properties": c_props,
                               "required": ["d", "u"] + [f["name"] for f in private if f.get("required")],
                               "additionalProperties": False}]}
    doc = {
        "$id": SAID_PLACEHOLDER, "$schema": "http://json-schema.org/draft-07/schema#",
        "title": title or name, "description": description, "type": "object",
        "credentialType": name, "version": version,
        "dzq": {"type": name, "version": version, "to": to, "public": public, "private": private},
        "properties": {"v": {"type": "string"}, "d": {"type": "string"}, "i": {"type": "string"},
                       "ri": {"type": "string"}, "s": {"type": "string"},
                       "a": {"type": "object", "properties": a_props,
                             "required": ["d", "dt"] + [f["name"] for f in public if f.get("required")],
                             "oneOf": recipients, "additionalProperties": False}},
        "required": ["v", "d", "i", "ri", "s", "a"], "additionalProperties": False,
    }
    said = blake3_said(_dumps(doc))
    doc["$id"] = said
    return said, _dumps(doc)


class TypeDoc:
    """A parsed type document."""

    def __init__(self, text, expect=None):
        try:
            doc = json.loads(text)
        except (json.JSONDecodeError, TypeError) as e:
            raise TypeError_("not JSON: %s" % e) from e
        if not isinstance(doc, dict) or not isinstance(doc.get("dzq"), dict):
            raise TypeError_("not a dzq type document (no dzq block)")
        said = doc.get("$id")
        if not isinstance(said, str) or blake3_said(text.replace('"%s"' % said, '"%s"' % SAID_PLACEHOLDER, 1)) != said:
            raise TypeError_("the type document's SAID does not match its content")
        if expect is not None and said != expect:
            raise TypeError_("this is not the type the statement names")
        z = doc["dzq"]
        if not isinstance(z.get("type"), str) or not NAME_RE.fullmatch(z["type"]):
            raise TypeError_("dzq.type must be <source>:<name>")
        self.said, self.text = said, text
        self.name, self.version = z["type"], str(z.get("version", ""))
        self.to = tuple(z.get("to") or ("aid", "condition"))
        self.public = _check_fields(z.get("public") or [], "public")
        self.private = _check_fields(z.get("private") or [], "private")
        self.title = doc.get("title") or self.name

    @property
    def source(self):
        return self.name.split(":", 1)[0]

    def fields(self, which):
        return self.public if which == "public" else self.private

    def __repr__(self):
        def fmt(fs):
            return ", ".join(f["name"] if f.get("required") else "[%s]" % f["name"] for f in fs) or "-"
        return "%s %s  public: %s  private: %s" % (self.name, self.version, fmt(self.public), fmt(self.private))

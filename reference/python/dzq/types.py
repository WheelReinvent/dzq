"""Statement types known to this reader.

A type is a type document (typedoc.py). dzq publishes a small library of
base types — gratitude, apology, promise — in the repository's
types/ folder; every reader knows them. None is special: they are ordinary
type documents under the reserved `dzq:` source. Anyone can define more
(`dzq type new`, or `typedoc.make_type`), e.g. `myapp:gratitude`. A reader
that does not know a type still verifies its statements (envelope, SAIDs,
signature); it just cannot check the fields.
"""

import os

from . import acdc
from .typedoc import TypeDoc, TypeError_, make_type  # noqa: F401

_TEXT = {"kind": "text"}


def _base(name, version, public, private, title, description):
    _, text = make_type("dzq:" + name, version, public=public, private=private, title=title, description=description)
    return TypeDoc(text)


GRATITUDE = _base(
    "gratitude", "1.2.0",
    public=[{"name": "category", "required": True, "max": 64}],
    private=[{"name": "title", "required": True, "max": 200},
             {"name": "message", "required": True, "max": 5000},
             {"name": "attachment", "kind": "attachment"}],
    title="dzq Gratitude",
    description="A signed thank-you. Category is public; title, message and attachment are in a salted private block.")
assert GRATITUDE.said == acdc.SCHEMA_GRATITUDE_12, "base gratitude type changed"

APOLOGY = _base(
    "apology", "1.0.0",
    public=[],
    private=[{"name": "title", "required": True, "max": 200},
             {"name": "message", "required": True, "max": 5000},
             {"name": "attachment", "kind": "attachment"}],
    title="dzq Apology",
    description="A signed apology. Nothing is public but the envelope: who, to whom, when.")

PROMISE = _base(
    "promise", "1.0.0",
    public=[{"name": "until", "max": 64, "description": "RFC 3339: the promise is not meant to hold after this"}],
    private=[{"name": "what", "required": True, "max": 200},
             {"name": "note", "max": 5000}],
    title="dzq Promise",
    description="A signed promise: what the issuer will do for the recipient, or for whoever meets the condition.")

BASE = {t.name: t for t in (GRATITUDE, APOLOGY, PROMISE)}
BUILTIN = {t.said: t for t in BASE.values()}

# Names reserved for the types this specification defines.
RESERVED_SOURCE = "dzq"


def accept(doc):
    """May a reader use this (carried or loaded) type document? Documents
    that claim the reserved `dzq:` source must be base types."""
    return doc.source != RESERVED_SOURCE or doc.said in BUILTIN


def load(path):
    """A type document from a file."""
    with open(path, encoding="utf-8") as f:
        doc = TypeDoc(f.read())
    if not accept(doc):
        raise TypeError_("%s claims the reserved dzq: source" % path)
    return doc


def load_dir(path):
    """Every *.json type document in a folder → {SAID: TypeDoc}."""
    out = {}
    if path and os.path.isdir(path):
        for name in sorted(os.listdir(path)):
            if name.endswith(".json"):
                try:
                    doc = load(os.path.join(path, name))
                    out[doc.said] = doc
                except (TypeError_, OSError):
                    pass
    return out


def find(name_or_said, known=None):
    """A type by SAID, by name (`acme:board-post`), or a short name
    (`gratitude`) for a base type. The newest version wins when several share a name."""
    pool = dict(BUILTIN)
    pool.update(known or {})
    if name_or_said in pool:
        return pool[name_or_said]
    name = name_or_said if ":" in name_or_said else "%s:%s" % (RESERVED_SOURCE, name_or_said)
    hits = [d for d in pool.values() if d.name == name]
    if not hits:
        raise ValueError("unknown type %r; known: %s" % (name_or_said, ", ".join(sorted({d.name for d in pool.values()}))))
    return max(hits, key=lambda d: tuple(int(x) for x in d.version.split(".")))


# Compatibility with earlier code paths.
TYPES = {t.name.split(":", 1)[1]: t for t in BASE.values()}


def by_name(name):
    return find(name)


def by_schema(said, known=None):
    return (known or {}).get(said) or BUILTIN.get(said)

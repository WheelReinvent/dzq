"""Statement types known to this reader.

A type is a type document (typedoc.py). dzq ships one built-in type,
`dzq:gratitude`. Anyone can define more: `dzq type new`, or
`typedoc.make_type`. A reader that does not know a type still verifies its
statements (envelope, SAIDs, signature); it just cannot check the fields.
"""

import os

from . import acdc
from .typedoc import TypeDoc, TypeError_, make_type  # noqa: F401

_said, _text = make_type(
    "dzq:gratitude", "1.2.0",
    public=[{"name": "category", "required": True, "max": 64}],
    private=[{"name": "title", "required": True, "max": 200},
             {"name": "message", "required": True, "max": 5000},
             {"name": "attachment", "kind": "attachment"}],
    title="dzq Gratitude",
    description="A signed thank-you. Category is public; title, message and attachment are in a salted private block.")
assert _said == acdc.SCHEMA_GRATITUDE_12, "built-in gratitude type changed"
GRATITUDE = TypeDoc(_text)

BUILTIN = {GRATITUDE.said: GRATITUDE}

# Names reserved for the types this specification defines.
RESERVED_SOURCE = "dzq"


def accept(doc):
    """May a reader use this (carried or loaded) type document? Documents
    that claim the reserved `dzq:` source must be built-in ones."""
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
    """A type by SAID, by name (`acme:board-post`), or `gratitude` for the
    built-in one. The newest version wins when several share a name."""
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
TYPES = {"gratitude": GRATITUDE}


def by_name(name):
    return find(name)


def by_schema(said, known=None):
    return (known or {}).get(said) or BUILTIN.get(said)

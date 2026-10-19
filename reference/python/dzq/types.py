"""Statement types: what is said inside the common envelope (SPEC §3, §8.5).

A type names its content fields and its schemas (one for a statement to an
AID, one for a statement to a condition). dzq/1.0 defines one type.
"""

from . import acdc


class Type:
    """A statement type: its fields, which of them stay public when the
    statement is shown compact, and its schemas."""

    def __init__(self, name, public, private, optional_private=(), schemas=(), private_schemas=()):
        self.name = name
        self.public = tuple(public)                 # always visible
        self.private = tuple(private)               # in the salted content block
        self.optional_private = tuple(optional_private)
        self.schema_to_aid, self.schema_to_condition = schemas
        self.private_schema_to_aid, self.private_schema_to_condition = private_schemas

    @property
    def required(self):
        return self.public + self.private

    @property
    def optional(self):
        return self.optional_private

    @property
    def fields(self):
        return self.required + self.optional

    @property
    def all_schemas(self):
        return (self.schema_to_aid, self.schema_to_condition, self.private_schema_to_aid, self.private_schema_to_condition)

    def __repr__(self):
        return "Type(%s: public %s; private %s%s)" % (
            self.name, ", ".join(self.public) or "-", ", ".join(self.private),
            "".join(", [%s]" % f for f in self.optional_private))


GRATITUDE = Type("gratitude", public=("category",), private=("title", "message"), optional_private=("attachment",),
                 schemas=(acdc.SCHEMA_GRATITUDE, acdc.SCHEMA_GRATITUDE_CONDITION),
                 private_schemas=(acdc.SCHEMA_GRATITUDE_PRIVATE, acdc.SCHEMA_GRATITUDE_PRIVATE_CONDITION))

TYPES = {t.name: t for t in (GRATITUDE,)}


def by_name(name):
    try:
        return TYPES[name]
    except KeyError:
        raise ValueError("unknown type %r; known: %s" % (name, ", ".join(TYPES))) from None


def by_schema(said):
    for t in TYPES.values():
        if said in t.all_schemas:
            return t
    return None

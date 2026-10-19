"""Statement types: what is said inside the common envelope (SPEC §3, §8.5).

A type names its content fields and its schemas (one for a statement to an
AID, one for a statement to a condition). dzq/1.0 defines one type.
"""

from . import acdc


class Type:
    def __init__(self, name, schema_to_aid, schema_to_condition, required, optional=()):
        self.name = name
        self.schema_to_aid = schema_to_aid
        self.schema_to_condition = schema_to_condition
        self.required = tuple(required)
        self.optional = tuple(optional)

    @property
    def fields(self):
        return self.required + self.optional

    def __repr__(self):
        return "Type(%s: %s)" % (self.name, ", ".join(self.required) + "".join(", [%s]" % f for f in self.optional))


GRATITUDE = Type("gratitude", acdc.SCHEMA_GRATITUDE, acdc.SCHEMA_GRATITUDE_CONDITION,
                 required=("title", "message", "category"), optional=("attachment",))

TYPES = {t.name: t for t in (GRATITUDE,)}


def by_name(name):
    try:
        return TYPES[name]
    except KeyError:
        raise ValueError("unknown type %r; known: %s" % (name, ", ".join(TYPES))) from None


def by_schema(said):
    for t in TYPES.values():
        if said in (t.schema_to_aid, t.schema_to_condition):
            return t
    return None

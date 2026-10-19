"""Statement types: what is said inside the common envelope (SPEC §3, §8.5).

A type names its fields — which stay public when the statement is shown
compact, which go into the salted private block — and its schemas.
"""

from . import acdc


class Type:
    def __init__(self, name, latest, schemas):
        self.name = name
        self.latest_to_aid, self.latest_to_condition = latest   # what new statements are issued under
        self.schemas = tuple(schemas)                             # every schema of this type a verifier accepts
        layout = acdc.LAYOUTS[self.latest_to_aid]
        self.public = tuple(f[0] for f in layout.public if f[1])
        self.optional_public = tuple(f[0] for f in layout.public if not f[1])
        self.private = tuple(f[0] for f in layout.content if f[1])
        self.optional_private = tuple(f[0] for f in layout.content if not f[1])

    @property
    def required(self):
        return self.public + self.private

    @property
    def optional(self):
        return self.optional_public + self.optional_private

    @property
    def fields(self):
        return self.required + self.optional

    @property
    def all_schemas(self):
        return self.schemas

    def __repr__(self):
        return "Type(%s: public %s; private %s)" % (
            self.name,
            ", ".join(self.public + tuple("[%s]" % f for f in self.optional_public)) or "-",
            ", ".join(self.private + tuple("[%s]" % f for f in self.optional_private)))


GRATITUDE = Type("gratitude", (acdc.SCHEMA_GRATITUDE_12, acdc.SCHEMA_GRATITUDE_12_CONDITION),
                 (acdc.SCHEMA_GRATITUDE, acdc.SCHEMA_GRATITUDE_CONDITION,
                  acdc.SCHEMA_GRATITUDE_PRIVATE, acdc.SCHEMA_GRATITUDE_PRIVATE_CONDITION,
                  acdc.SCHEMA_GRATITUDE_12, acdc.SCHEMA_GRATITUDE_12_CONDITION))
CERTIFICATE = Type("certificate", (acdc.SCHEMA_CERTIFICATE, acdc.SCHEMA_CERTIFICATE_CONDITION),
                   (acdc.SCHEMA_CERTIFICATE, acdc.SCHEMA_CERTIFICATE_CONDITION))

TYPES = {t.name: t for t in (GRATITUDE, CERTIFICATE)}


def by_name(name):
    try:
        return TYPES[name]
    except KeyError:
        raise ValueError("unknown type %r; known: %s" % (name, ", ".join(TYPES))) from None


def by_schema(said):
    for t in TYPES.values():
        if said in t.schemas:
            return t
    return None

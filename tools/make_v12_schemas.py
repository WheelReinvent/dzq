#!/usr/bin/env python3
"""Writes the dzq/1.2 schemas (gratitude 1.2.0/2.2.0, certificate 1.1.0/2.1.0,
look/1) and their SAIDs. Existing files are never changed."""

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "reference", "python"))
from dzq.cesr import SAID_PLACEHOLDER, blake3_said  # noqa: E402

S = {"type": "string"}
ATTACHMENT = {"type": "object", "properties": {
    "d": {"type": "string", "description": "BLAKE3-256 hex digest of the file"},
    "filename": S, "mime_type": S, "size": {"type": "integer"}},
    "required": ["d", "filename", "mime_type", "size"], "additionalProperties": False}
LOOK = {"type": "string", "pattern": "^[a-z0-9-]+:[^\\s]+$",
        "description": "<source>:<id> — where to ask, and the SAID (or a name) of the look/1 document"}
SALT = {"type": "string", "description": "Salt: 128 random bits, CESR qb64 (0A…)"}
RECIPIENT = {"i": {"type": "string", "description": "Recipient AID"}}
CONDITION = {"dq": {"type": "string", "maxLength": 65536,
                    "description": "Condition: any(…) | all(…) | <AID> | claim:<hex> | thanks:<N>/<category>/<issuers>[@<since>] | <kind>:<value>"}}


def content(props, required):
    return {"oneOf": [{"type": "string", "description": "Compact form: the SAID of the content block"},
                      {"type": "object", "properties": dict({"d": S, "u": SALT}, **props),
                       "required": ["d", "u"] + required, "additionalProperties": False}]}


def acdc_schema(version, title, description, ctype, a_props, a_required):
    return {"$id": "%SAID%", "$schema": "http://json-schema.org/draft-07/schema#",
            "title": title, "description": description, "type": "object",
            "credentialType": ctype, "version": version,
            "properties": {"v": S, "d": S, "i": S, "ri": S, "s": S,
                           "a": {"type": "object", "properties": a_props, "required": a_required,
                                 "additionalProperties": False}},
            "required": ["v", "d", "i", "ri", "s", "a"], "additionalProperties": False}


GRAT_C = content({"title": {"type": "string", "maxLength": 200}, "message": {"type": "string", "maxLength": 5000},
                  "attachment": ATTACHMENT, "look": LOOK}, ["title", "message"])
CERT_C = content({"what": {"type": "string", "maxLength": 200}, "note": {"type": "string", "maxLength": 5000},
                  "look": LOOK}, ["what"])
DT = {"type": "string", "format": "date-time"}


def gratitude(version, to):
    rf = "i" if to == "aid" else "dq"
    props = dict({"d": S}, **(RECIPIENT if to == "aid" else CONDITION))
    props.update({"dt": DT, "category": {"type": "string", "maxLength": 64}, "c": GRAT_C})
    return acdc_schema(version, "dzq Gratitude" + ("" if to == "aid" else " (condition)"),
                       "A signed thank-you. Title, message, attachment and look are in a salted block that can be "
                       "shown, or replaced by its SAID without breaking the signature.",
                       "DzqGratitude", props, ["d", rf, "dt", "category", "c"])


def certificate(version, to):
    rf = "i" if to == "aid" else "dq"
    props = dict({"d": S}, **(RECIPIENT if to == "aid" else CONDITION))
    props.update({"dt": DT, "until": DT, "c": CERT_C})
    return acdc_schema(version, "dzq Certificate" + ("" if to == "aid" else " (condition)"),
                       "A signed promise from the issuer to whoever meets its condition. What is promised, a note "
                       "and the look are in a salted block. No use counter; the issuer may close it early.",
                       "DzqCertificate", props, ["d", rf, "dt", "c"])


COLOR = {"type": "string", "pattern": "^#[0-9A-Fa-f]{6}$"}
FILE = {"type": "string", "description": "SAID (Blake3-256 qb64) of a file: PNG, JPEG, WebP or WOFF2"}
PARTS = {
    "background": {"type": "object", "properties": {"color": COLOR, "image": FILE, "fit": {"enum": ["cover", "tile"]}}},
    "text": {"type": "object", "properties": {"color": COLOR, "align": {"enum": ["start", "center"]}, "font": {
        "oneOf": [{"enum": ["serif", "sans", "hand", "mono"]},
                  {"type": "object", "properties": {"file": FILE, "family": S}, "required": ["file", "family"]}]}}},
    "accent": COLOR,
    "frame": {"type": "object", "properties": {"style": {"enum": ["none", "line", "double", "ornament"]}, "color": COLOR}},
    "emblem": {"type": "object", "properties": {"image": FILE, "place": {"enum": ["top", "corner", "none"]}}},
}
LOOK_DOC = {"$id": "%SAID%", "$schema": "http://json-schema.org/draft-07/schema#", "title": "dzq look",
            "description": "How a statement wants to be shown: data only, a hint. Unknown fields are ignored.",
            "type": "object", "version": "1.0.0",
            "properties": dict({"v": {"const": "look/1"}, "d": S, "name": {"type": "string", "maxLength": 64},
                                "layout": {"enum": ["card", "letter", "ticket"]}},
                               **PARTS, dark={"type": "object", "properties": PARTS}),
            "required": ["v", "d", "name"]}

SCHEMAS = {
    "gratitude-1.2.schema.json": gratitude("1.2.0", "aid"),
    "gratitude-condition-1.2.schema.json": gratitude("2.2.0", "condition"),
    "certificate.schema.json": certificate("1.1.0", "aid"),
    "certificate-condition.schema.json": certificate("2.1.0", "condition"),
    "look.schema.json": LOOK_DOC,
}

index_path = os.path.join(ROOT, "schemas", "index.json")
index = json.load(open(index_path, encoding="utf-8"))
for name, sch in SCHEMAS.items():
    text = json.dumps(sch, ensure_ascii=False, separators=(",", ":"))
    said = blake3_said(text.replace('"%SAID%"', '"%s"' % SAID_PLACEHOLDER))
    body = text.replace('"%SAID%"', '"%s"' % said)
    path = os.path.join(ROOT, "schemas", name)
    if os.path.exists(path) and open(path, encoding="utf-8").read() != body:
        sys.exit("refusing to change existing schema %s" % name)
    open(path, "w", encoding="utf-8").write(body)
    index[name] = {"said": said, "title": sch["title"], "version": sch["version"],
                   "credentialType": sch.get("credentialType", "look")}
    print("%-40s %s" % (name, said))
with open(index_path, "w", encoding="utf-8") as f:
    json.dump(index, f, indent=2, ensure_ascii=False)
    f.write("\n")

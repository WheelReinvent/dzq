#!/usr/bin/env python3
"""Writes the private-content gratitude schemas (1.1.0, 2.1.0) and their SAIDs.
Run once; the files are then byte-exact and must never change."""

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "reference", "python"))
from dzq.cesr import SAID_PLACEHOLDER, blake3_said  # noqa: E402

ATTACHMENT = {"type": "object", "properties": {
    "d": {"type": "string", "description": "BLAKE3-256 hex digest of the file"},
    "filename": {"type": "string"}, "mime_type": {"type": "string"}, "size": {"type": "integer"}},
    "required": ["d", "filename", "mime_type", "size"], "additionalProperties": False}

CONTENT = {"oneOf": [
    {"type": "string", "description": "Compact form: the SAID of the content block"},
    {"type": "object", "properties": {
        "d": {"type": "string"},
        "u": {"type": "string", "description": "Salt: 128 random bits, CESR qb64 (0A…)"},
        "title": {"type": "string", "maxLength": 200},
        "message": {"type": "string", "maxLength": 5000},
        "attachment": ATTACHMENT},
     "required": ["d", "u", "title", "message"], "additionalProperties": False}]}


def schema(version, title, description, recipient_field, recipient_schema):
    a_props = {"d": {"type": "string"}, recipient_field: recipient_schema,
               "dt": {"type": "string", "format": "date-time"},
               "category": {"type": "string", "maxLength": 64}, "c": CONTENT}
    return {"$id": "%SAID%", "$schema": "http://json-schema.org/draft-07/schema#",
            "title": title, "description": description, "type": "object",
            "credentialType": "DzqGratitude", "version": version,
            "properties": {"v": {"type": "string"}, "d": {"type": "string"}, "i": {"type": "string"},
                           "ri": {"type": "string"}, "s": {"type": "string"},
                           "a": {"type": "object", "properties": a_props,
                                 "required": ["d", recipient_field, "dt", "category", "c"],
                                 "additionalProperties": False}},
            "required": ["v", "d", "i", "ri", "s", "a"], "additionalProperties": False}


SCHEMAS = {
    "gratitude-private.schema.json": schema(
        "1.1.0", "dzq Gratitude (private content)",
        "A signed thank-you to one identifier. Title, message and attachment are in a salted block "
        "that can be shown, or replaced by its SAID without breaking the signature.",
        "i", {"type": "string", "description": "Recipient AID"}),
    "gratitude-private-condition.schema.json": schema(
        "2.1.0", "dzq Gratitude (private content, condition)",
        "A signed thank-you to whoever meets its condition. Title, message and attachment are in a "
        "salted block that can be shown, or replaced by its SAID without breaking the signature.",
        "dq", {"type": "string", "maxLength": 65536, "description": "Condition: any(…) | all(…) | <AID> | claim:<hex> | <kind>:<value>"}),
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
    index[name] = {"said": said, "title": sch["title"], "version": sch["version"], "credentialType": sch["credentialType"]}
    print(name, said)
with open(index_path, "w", encoding="utf-8") as f:
    json.dump(index, f, indent=2, ensure_ascii=False)
    f.write("\n")

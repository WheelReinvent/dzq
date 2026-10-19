"""Looks: how a statement wants to be shown (proposals 0003, 0004).

A statement may name a look in its private block: `look = "<source>:<id>"`,
where the id is the SAID of a look/1 document (or, for now, a plain name).
A look is a hint: it never affects validity.
"""

import json
import re

from .cesr import SAID_PLACEHOLDER, blake3_said

MAX_TOTAL = 2 * 1024 * 1024
COLOR = re.compile(r"#[0-9A-Fa-f]{6}")
SAID_RE = re.compile(r"E[A-Za-z0-9_-]{43}")
FILE_MAGIC = {
    "png": (b"\x89PNG\r\n\x1a\n",),
    "jpeg": (b"\xff\xd8\xff",),
    "webp": (b"RIFF",),          # plus "WEBP" at offset 8
    "woff2": (b"wOF2",),
}


class LookError(ValueError):
    pass


def split_ref(ref):
    """`<source>:<id>` → (source, id, is_said)."""
    source, _, ident = ref.partition(":")
    return source, ident, bool(SAID_RE.fullmatch(ident))


def file_kind(data):
    if data.startswith(FILE_MAGIC["png"][0]):
        return "png"
    if data.startswith(FILE_MAGIC["jpeg"][0]):
        return "jpeg"
    if data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return "webp"
    if data.startswith(b"wOF2"):
        return "woff2"
    return None


def document_said(doc):
    tmp = dict(doc)
    tmp["d"] = SAID_PLACEHOLDER
    return blake3_said(json.dumps(tmp, ensure_ascii=False, separators=(",", ":")))


def make_document(doc):
    """Fills `d` of a look/1 document; returns (said, canonical JSON text)."""
    doc = {"v": "look/1", "d": "", **{k: v for k, v in doc.items() if k not in ("v", "d")}}
    doc["d"] = document_said(doc)
    return doc["d"], json.dumps(doc, ensure_ascii=False, separators=(",", ":"))


def _files_of(part, out):
    if not isinstance(part, dict):
        return
    bg = part.get("background")
    if isinstance(bg, dict) and isinstance(bg.get("image"), str):
        out.append(("image", bg["image"]))
    em = part.get("emblem")
    if isinstance(em, dict) and isinstance(em.get("image"), str):
        out.append(("image", em["image"]))
    tx = part.get("text")
    if isinstance(tx, dict) and isinstance(tx.get("font"), dict) and isinstance(tx["font"].get("file"), str):
        out.append(("font", tx["font"]["file"]))


def files_of(doc):
    out = []
    _files_of(doc, out)
    _files_of(doc.get("dark"), out)
    return out


def check_document(text, files=None, expect=None):
    """Checks a look/1 document (its text) and the files it names.

    `files` maps file SAID → bytes (missing files are allowed: the renderer
    drops that part). Returns the parsed document. Raises LookError."""
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as e:
        raise LookError("not JSON: %s" % e) from e
    if not isinstance(doc, dict) or doc.get("v") != "look/1":
        raise LookError("not a look/1 document")
    if not isinstance(doc.get("name"), str) or not doc["name"] or len(doc["name"]) > 64:
        raise LookError("name is required, at most 64 characters")
    if document_said(doc) != doc.get("d"):
        raise LookError("the look's SAID does not match its content")
    if expect is not None and doc["d"] != expect:
        raise LookError("this is not the look the statement names")
    for part in (doc, doc.get("dark") or {}):
        for key in ("accent",):
            if key in part and not (isinstance(part[key], str) and COLOR.fullmatch(part[key])):
                raise LookError("%s must be #RRGGBB" % key)
        for sub in ("background", "text", "frame"):
            if isinstance(part.get(sub), dict) and "color" in part[sub]:
                c = part[sub]["color"]
                if not (isinstance(c, str) and COLOR.fullmatch(c)):
                    raise LookError("%s.color must be #RRGGBB" % sub)
    total = len(text.encode("utf-8"))
    for kind, said in files_of(doc):
        body = (files or {}).get(said)
        if body is None:
            continue
        if blake3_said(body) != said:
            raise LookError("file %s does not match its SAID" % said[:12])
        k = file_kind(body)
        if kind == "image" and k not in ("png", "jpeg", "webp"):
            raise LookError("images must be PNG, JPEG or WebP")
        if kind == "font" and k != "woff2":
            raise LookError("fonts must be WOFF2")
        total += len(body)
    if total > MAX_TOTAL:
        raise LookError("a look and its files are at most 2 MB")
    return doc

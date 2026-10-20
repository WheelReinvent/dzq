"""The `.dzq` file: a ZIP archive around one credential bundle (dzq/1.0 §5)."""

import io
import json
import zipfile

from . import verify
from .blake3 import blake3

MAX_INPUT = 25 * 1024 * 1024
MAX_ENTRIES = 20
MAX_ENTRY = 20 * 1024 * 1024
MAX_TOTAL = 25 * 1024 * 1024

CREDENTIAL = "credential.acdc"
METADATA = "metadata.json"            # optional, display only, never trusted
SIGNATURES = "signatures.json"        # deprecated: ignored when read, not written


class ArchiveError(ValueError):
    pass


def asset_basename(entry):
    if not entry.startswith("assets/"):
        return None
    name = entry[len("assets/"):]
    ok = (name and len(name.encode("utf-8")) <= 255 and not name.startswith(".")
          and not any(c in name for c in "/\\:\0") and ".." not in name)
    return name if ok else None


def look_entry(name):
    """`looks/<SAID>.json` (a look/1 document) or `looks/<SAID>` (a file it uses)."""
    from .look import SAID_RE
    if not name.startswith("looks/"):
        return None
    rest = name[len("looks/"):]
    said = rest[:-5] if rest.endswith(".json") else rest
    return said if SAID_RE.fullmatch(said) else None


def type_entry(name):
    """`types/<SAID>.json`: a type document carried with the statement."""
    from .look import SAID_RE
    if not (name.startswith("types/") and name.endswith(".json")):
        return None
    said = name[len("types/"):-5]
    return said if SAID_RE.fullmatch(said) else None


def _safe_name(name):
    return not (name.startswith("/") or "\\" in name or ".." in name.split("/") or ":" in name.split("/")[0])


def open_dzq(data):
    """Reads a .dzq archive safely. Returns (credential bundle text, ZipFile)."""
    if len(data) > MAX_INPUT:
        raise ArchiveError("archive too large")
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        infos = z.infolist()
    except zipfile.BadZipFile as e:
        raise ArchiveError("not a ZIP archive") from e
    if len(infos) > MAX_ENTRIES:
        raise ArchiveError("too many entries")
    total = 0
    for info in infos:
        name = info.filename
        if not _safe_name(name):
            raise ArchiveError("unsafe entry name %r" % name)
        allowed = (name in (CREDENTIAL, METADATA, SIGNATURES, "assets/", "looks/", "types/")
                   or asset_basename(name) or look_entry(name) or type_entry(name))
        if not allowed:
            raise ArchiveError("unexpected entry %r" % name)
        if info.file_size > MAX_ENTRY:
            raise ArchiveError("entry %r too large" % name)
        total += info.file_size
        if total > MAX_TOTAL:
            raise ArchiveError("archive expands too large")
    try:
        cred = _read(z, CREDENTIAL)
    except KeyError as e:
        raise ArchiveError("no credential.acdc") from e
    try:
        return cred.decode("utf-8"), z
    except UnicodeDecodeError as e:
        raise ArchiveError("credential.acdc is not UTF-8") from e


def _read(z, name):
    with z.open(name) as f:
        data = f.read(MAX_ENTRY + 1)
    if len(data) > MAX_ENTRY:
        raise ArchiveError("entry %r too large" % name)
    return data


def read_dzq(data):
    """What a .dzq says, WITHOUT checking it: issuer, recipient (or condition),
    date, the type's fields, attachment names. Call check_dzq to know whether
    to believe it."""
    bundle, z = open_dzq(data)
    a = json.loads(verify.split_bundle(bundle)[0])
    attrs = a.get("a", {})
    c = attrs.get("c") if isinstance(attrs.get("c"), dict) else {}
    fields = {k: v for k, v in attrs.items() if k not in ("d", "i", "req", "dq", "dt", "c")}
    fields.update({k: v for k, v in c.items() if k not in ("d", "u")})
    return {"issuer": a.get("i"), "recipient": attrs.get("i") or attrs.get("req") or attrs.get("dq"), "date": attrs.get("dt"),
            "schema": a.get("s"), "fields": fields,
            "title": fields.get("title"), "message": fields.get("message"), "category": fields.get("category"),
            "attachment": (named_attachment(a) or {}).get("filename"),
            "hidden": isinstance(attrs.get("c"), str)}


def _is_attachment(v):
    return isinstance(v, dict) and set(v) == {"d", "filename", "mime_type", "size"}


def named_attachments(credential):
    """Every file the statement names: attachment-shaped values in its public
    fields and its (disclosed) private block."""
    a = credential.get("a", {})
    c = a.get("c") if isinstance(a.get("c"), dict) else {}
    return [v for block in (a, c) for k, v in block.items() if k != "c" and _is_attachment(v)]


def named_attachment(credential):
    """The first file the statement names, or None."""
    found = named_attachments(credential)
    return found[0] if found else None


def carried_types(z):
    """{SAID: TypeDoc} for the valid `types/<SAID>.json` entries of an archive.
    Documents whose SAID does not match their name, or that claim the
    reserved dzq: source, are ignored."""
    from . import types as types_
    from .typedoc import TypeDoc, TypeError_
    out = {}
    for name in z.namelist():
        said = type_entry(name)
        if said is None:
            continue
        try:
            doc = TypeDoc(_read(z, name).decode("utf-8"), expect=said)
        except (TypeError_, UnicodeDecodeError):
            continue
        if types_.accept(doc):
            out[said] = doc
    return out


def check_dzq(data, seal=None, kel_text=None, known=None):
    """Verifies a .dzq file. A type document carried as types/<SAID>.json is
    used when the reader does not know the type. Adds `attachment`: None
    (none named), "ok", "missing" or "mismatch" (a file is not the one the
    statement names)."""
    bundle, z = open_dzq(data)
    pool = carried_types(z)
    pool.update(known or {})
    r = verify.check_credential(bundle, seal=seal, kel_text=kel_text, known=pool)
    att = None
    if r.valid:
        for named in named_attachments(json.loads(verify.split_bundle(bundle)[0])):
            entry = "assets/" + str(named["filename"])
            if asset_basename(entry) is None:
                att = "mismatch"
                break
            try:
                body = _read(z, entry)
            except KeyError:
                att = "missing"
                break
            if blake3(body).hex() != named["d"] or len(body) != named["size"]:
                att = "mismatch"
                break
            att = "ok"
    r["attachment"] = att
    r["look"] = _check_look(z, bundle) if r.valid else None
    return r


def _check_look(z, bundle):
    """None (no look), "named" (named, not carried), "ok", or "invalid: …"."""
    from . import look as look_
    cred = json.loads(verify.split_bundle(bundle)[0])
    c = cred.get("a", {}).get("c")
    ref = c.get("look") if isinstance(c, dict) else None
    if not ref:
        return None
    _, ident, is_said = look_.split_ref(ref)
    names = set(z.namelist())
    if not is_said or "looks/%s.json" % ident not in names:
        return "named"
    files = {n[len("looks/"):]: _read(z, n) for n in names
             if n.startswith("looks/") and not n.endswith(".json") and n != "looks/"}
    try:
        look_.check_document(_read(z, "looks/%s.json" % ident).decode("utf-8"), files, expect=ident)
        return "ok"
    except (look_.LookError, UnicodeDecodeError) as e:
        return "invalid: %s" % e


def make_dzq(bundle, metadata=None, attachment=None, look=None, type_doc=None, attachments=()):
    """Writes a .dzq archive: credential.acdc, optional metadata.json,
    assets/<filename> (attachment = (filename, bytes), or several in
    `attachments`), the type document as types/<SAID>.json (`type_doc`, a
    TypeDoc) and a look/1 document (extension: looks)."""
    entries = [(CREDENTIAL, bundle.encode("utf-8"))]
    if metadata is not None:
        entries.append((METADATA, json.dumps(metadata, ensure_ascii=False, indent=2).encode("utf-8")))
    for name, body in ([attachment] if attachment is not None else []) + list(attachments):
        entries.append(("assets/" + name, body))
    if type_doc is not None:
        entries.append(("types/%s.json" % type_doc.said, type_doc.text.encode("utf-8")))
    if look is not None:   # (said, document text, {file said: bytes})
        said, text, files = look
        entries.append(("looks/%s.json" % said, text.encode("utf-8")))
        for fs, body in sorted(files.items()):
            entries.append(("looks/" + fs, body))
    return zip_entries(entries)


def zip_entries(entries):
    """A reproducible ZIP (fixed timestamps, deflate) of (name, bytes) pairs."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, body in entries:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            z.writestr(info, body)
    return buf.getvalue()

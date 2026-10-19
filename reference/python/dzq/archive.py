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
        allowed = name in (CREDENTIAL, METADATA, SIGNATURES, "assets/") or asset_basename(name)
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


def check_dzq(data, seal=None, kel_text=None):
    """Verifies a .dzq file. Adds `attachment`: None (none named), "ok",
    "missing" or "mismatch" (the file is not the one the credential names)."""
    bundle, z = open_dzq(data)
    r = verify.check_credential(bundle, seal=seal, kel_text=kel_text)
    att = None
    if r.valid:
        a = verify.split_bundle(bundle)[0]
        named = json.loads(a)["a"].get("attachment")
        if named:
            entry = "assets/" + named["filename"]
            if asset_basename(entry) is None:
                att = "mismatch"
            else:
                try:
                    body = _read(z, entry)
                    att = "ok" if blake3(body).hex() == named["d"] and len(body) == named["size"] else "mismatch"
                except KeyError:
                    att = "missing"
    r["attachment"] = att
    return r


def make_dzq(bundle, metadata=None, attachment=None):
    """Writes a dzq/1.0 archive: credential.acdc, optional metadata.json and
    optional assets/<filename> (attachment = (filename, bytes))."""
    entries = [(CREDENTIAL, bundle.encode("utf-8"))]
    if metadata is not None:
        entries.append((METADATA, json.dumps(metadata, ensure_ascii=False, indent=2).encode("utf-8")))
    if attachment is not None:
        entries.append(("assets/" + attachment[0], attachment[1]))
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

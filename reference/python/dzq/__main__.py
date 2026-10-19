"""dzq on the command line: create an identity, sign, open, verify.

    dzq init alice                        # creates alice.id (keep it private)
    dzq types                             # what you can sign, and its fields
    dzq sign --as alice.id --type gratitude --to <AID> \\
             title="Thank you" message="For fixing my bike." category=help \\
             -o thanks.dzq
    dzq open thanks.dzq                   # what the file says (trusts nothing)
    dzq verify thanks.dzq                 # whether to believe it
    dzq hide thanks.dzq -o shown.dzq      # a copy without the private text, still valid
    dzq sign --as bob.id --type promise --to "thanks:3/help/<AID>" what="Lunch" -o lunch.dzq
    dzq present --as alice.id --nonce CODE lunch.dzq thanks*.dzq -o vp.json
    dzq presentation vp.json --nonce CODE --kel bob.kel
    dzq close --as bob.id lunch.dzq       # the issuer closes a promise early
    dzq kel bob.id -o bob.kel             # export a key history
    dzq look make gold.json -o looks/     # build a look/1 document and its files
    dzq presentation vp.json --nonce CODE
"""

import argparse
import json
import os
import sys

from . import archive, types, verify
from .identity import Identity
from .statement import Verification, open_statement

EXIT_VALID, EXIT_INVALID, EXIT_ERROR = 0, 1, 2


class CliError(Exception):
    pass


def _load_identity(path):
    try:
        with open(path, encoding="utf-8") as f:
            return Identity.from_json(f.read())
    except (OSError, KeyError, ValueError, json.JSONDecodeError) as e:
        raise CliError("cannot read identity %s: %s" % (path, e)) from e


def _save_identity(me, path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(me.to_json())


def cmd_init(a):
    path = a.name if a.name.endswith(".id") else a.name + ".id"
    if os.path.exists(path) and not a.force:
        raise CliError("%s already exists (use --force to replace it)" % path)
    me = Identity.create()
    _save_identity(me, path)
    print("created %s  (private: it holds your signing secret)" % path)
    print("your AID: %s" % me.aid)
    return EXIT_VALID


def cmd_whoami(a):
    print(_load_identity(a.identity).aid)
    return EXIT_VALID


def cmd_types(a):
    for t in types.TYPES.values():
        print("%s" % t.name)
        print("  public:   %s" % (", ".join(t.public + tuple("[%s]" % f for f in t.optional_public)) or "-"))
        print("  private:  %s" % ", ".join(t.private + tuple("[%s]" % f for f in t.optional_private)))
    print("\n[optional]. attachment: use --attach FILE. look: look=<source>:<id>, or --look-doc FILE.")
    return EXIT_VALID


def cmd_sign(a):
    me = _load_identity(a.identity)
    content = {}
    for kv in a.fields:
        if "=" not in kv:
            raise CliError("fields are name=value, got %r" % kv)
        k, v = kv.split("=", 1)
        content[k] = v
    attachment = None
    if a.attach:
        import mimetypes
        with open(a.attach, "rb") as f:
            body = f.read()
        attachment = (os.path.basename(a.attach), body, mimetypes.guess_type(a.attach)[0] or "application/octet-stream")
    look_bundle = None
    if a.look_doc:
        from . import look as look_
        try:
            text = open(a.look_doc, encoding="utf-8").read()
            doc = look_.check_document(text)
        except look_.LookError as e:
            raise CliError("look: %s" % e) from e
        folder = os.path.dirname(os.path.abspath(a.look_doc))
        files = {}
        for _, fs in look_.files_of(doc):
            fp = os.path.join(folder, fs)
            if os.path.exists(fp):
                files[fs] = open(fp, "rb").read()
        try:
            look_.check_document(text, files)
        except look_.LookError as e:
            raise CliError("look: %s" % e) from e
        content["look"] = "%s:%s" % (a.look_source, doc["d"])
        look_bundle = (doc["d"], text, files)
    try:
        st = me.sign(type=a.type, to=a.to, content=content, attachment=attachment, private=not a.all_public)
    except ValueError as e:
        raise CliError(str(e)) from e
    out = a.output or "%s.dzq" % st.said[:12]
    from . import archive as archive_
    data = st.to_dzq() if look_bundle is None else archive_.make_dzq(
        st.bundle, attachment=st._attachment, look=look_bundle)
    with open(out, "wb") as f:
        f.write(data)
    print(st)
    print("\nwrote %s" % out)
    return EXIT_VALID


def cmd_open(a):
    data = open(a.file, "rb").read()
    try:
        print(open_statement(data))
    except (archive.ArchiveError, ValueError) as e:
        raise CliError("not a readable dzq file: %s" % e) from e
    print("\n(not verified yet — run: dzq verify %s)" % a.file)
    return EXIT_VALID


def cmd_hide(a):
    data = open(a.file, "rb").read()
    try:
        st = open_statement(data)
    except (archive.ArchiveError, ValueError) as e:
        raise CliError("not a readable dzq file: %s" % e) from e
    if not st.private:
        raise CliError("this statement has no private part (it was signed with every field public)")
    shown = st.compact()
    out = a.output or a.file.replace(".dzq", "") + ".hidden.dzq"
    with open(out, "wb") as f:
        f.write(shown.to_dzq())
    print(shown)
    print("\nwrote %s — same statement, same signature, without the private text" % out)
    return EXIT_VALID


def _open(path):
    try:
        return open_statement(open(path, "rb").read())
    except (archive.ArchiveError, ValueError) as e:
        raise CliError("%s is not a readable dzq file: %s" % (path, e)) from e


def cmd_close(a):
    me = _load_identity(a.identity)
    st = _open(a.file)
    try:
        sn = me.close(st)
    except ValueError as e:
        raise CliError(str(e)) from e
    _save_identity(me, a.identity)
    print("closed %s at event %d of your key history" % (st.said, sn))
    print("verifiers see it once they have your current key history (dzq kel %s)" % a.identity)
    return EXIT_VALID


def cmd_kel(a):
    me = _load_identity(a.identity)
    if a.output:
        with open(a.output, "w", encoding="utf-8") as f:
            f.write(me.kel())
        print("wrote %s (%d events)" % (a.output, me.sn + 1))
    else:
        print(me.kel())
    return EXIT_VALID


def cmd_present(a):
    me = _load_identity(a.identity)
    statements = [_open(f) for f in a.files]
    vp = me.present(statements, a.nonce, compact=not a.full)
    with open(a.output, "w", encoding="utf-8") as f:
        f.write(vp)
    print("wrote %s: %d statement(s), %s, signed over code %s" % (
        a.output, len(statements), "with their private content" if a.full else "private content hidden", a.nonce))
    return EXIT_VALID


def cmd_look(a):
    from . import look as look_
    from .cesr import blake3_said
    if a.action == "make":
        spec = json.load(open(a.file, encoding="utf-8"))
        folder = os.path.dirname(os.path.abspath(a.file))
        files = {}

        def swap(part, key):
            if isinstance(part, dict) and isinstance(part.get(key), str) and not look_.SAID_RE.fullmatch(part[key]):
                body = open(os.path.join(folder, part[key]), "rb").read()
                part[key] = blake3_said(body)
                files[part[key]] = body
        for p in (spec, spec.get("dark") or {}):
            swap(p.get("background"), "image")
            swap(p.get("emblem"), "image")
            if isinstance(p.get("text"), dict):
                swap(p["text"].get("font"), "file")
        said, text = look_.make_document(spec)
        try:
            look_.check_document(text, files)
        except look_.LookError as e:
            raise CliError("look: %s" % e) from e
        os.makedirs(a.output, exist_ok=True)
        with open(os.path.join(a.output, said + ".json"), "w", encoding="utf-8") as f:
            f.write(text)
        for fs, body in files.items():
            with open(os.path.join(a.output, fs), "wb") as f:
                f.write(body)
        print("look %s\nwrote %s/%s.json and %d file(s)" % (said, a.output, said, len(files)))
        print("sign with: --look-doc %s/%s.json --look-source <your app>" % (a.output, said))
        return EXIT_VALID
    text = open(a.file, encoding="utf-8").read()
    folder = os.path.dirname(os.path.abspath(a.file))
    try:
        doc = look_.check_document(text)
        files = {fs: open(os.path.join(folder, fs), "rb").read()
                 for _, fs in look_.files_of(doc) if os.path.exists(os.path.join(folder, fs))}
        look_.check_document(text, files)
    except look_.LookError as e:
        print("✗ NOT A VALID LOOK: %s" % e)
        return EXIT_INVALID
    print("✓ look/1 \"%s\"  %s  (%d of %d files present)" % (doc["name"], doc["d"], len(files), len(look_.files_of(doc))))
    return EXIT_VALID


def cmd_verify(a):
    seal = json.load(open(a.seal, encoding="utf-8")) if a.seal else None
    kel_text = open(a.kel, encoding="utf-8").read() if a.kel else None
    data = open(a.file, "rb").read()
    if data[:2] == b"PK":
        try:
            r = archive.check_dzq(data, seal=seal, kel_text=kel_text)
        except archive.ArchiveError as e:
            r = verify.Result().fail("archive", str(e))
    else:
        r = verify.check_credential(data.decode("utf-8"), seal=seal, kel_text=kel_text)
    print(json.dumps(r, ensure_ascii=False, indent=2) if a.json else Verification(r))
    return EXIT_VALID if r["valid"] else EXIT_INVALID


def cmd_presentation(a):
    kels = [open(k, encoding="utf-8").read() for k in (a.kel or [])]
    r = verify.verify_presentation(open(a.file, encoding="utf-8").read(), a.nonce, kels=kels)
    if a.json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    else:
        print("✓ VALID" if r["valid"] else "✗ NOT VALID: %s (%s)" % (r.get("reason"), r.get("code")))
        print("  holder     %s" % r.get("holder"))
        if r["valid"] and not a.nonce:
            print("  note: no verifier code was given, so this only shows; it does not prove freshness")
        for c in r["credentials"]:
            ok = c.get("usable", c.get("holder_is_recipient"))
            label = c.get("type") or "?"
            why = ""
            if c.get("type") == "promise":
                why = "usable" if c.get("usable") else Verification.REASONS.get(c.get("why"), c.get("why"))
            elif not c.get("valid"):
                why = c.get("reason")
            elif not c.get("holder_is_recipient"):
                why = "not the holder's"
            print("  %s %-11s %s  %s" % ("✓" if ok else "✗", label, c.get("said") or "", why))
    return EXIT_VALID if r["valid"] else EXIT_INVALID


def main(argv=None):
    p = argparse.ArgumentParser(prog="dzq", description="dzq/1.0: signed statements between people")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="create an identity file (NAME.id)")
    s.add_argument("name")
    s.add_argument("--force", action="store_true")
    s.set_defaults(fn=cmd_init)

    s = sub.add_parser("whoami", help="print the AID of an identity file")
    s.add_argument("identity")
    s.set_defaults(fn=cmd_whoami)

    s = sub.add_parser("types", help="list statement types and their fields")
    s.set_defaults(fn=cmd_types)

    s = sub.add_parser("sign", help="sign a statement into a .dzq file")
    s.add_argument("--as", dest="identity", required=True, help="your identity file")
    s.add_argument("--type", required=True, help="statement type, see: dzq types")
    s.add_argument("--to", required=True, help="recipient AID, or a condition like any(AID,AID)")
    s.add_argument("fields", nargs="*", help="the type's fields as name=value")
    s.add_argument("--attach", help="a file to attach")
    s.add_argument("-o", "--output", help="output .dzq file")
    s.add_argument("--all-public", action="store_true",
                   help="dzq/1.0 layout: no private part, every field public forever")
    s.add_argument("--look-doc", help="a look/1 document to name and carry in the file")
    s.add_argument("--look-source", default="local", help="where others can ask for this look (default: local)")
    s.set_defaults(fn=cmd_sign)

    s = sub.add_parser("close", help="close a promise you issued (no longer usable by anyone)")
    s.add_argument("--as", dest="identity", required=True)
    s.add_argument("file")
    s.set_defaults(fn=cmd_close)

    s = sub.add_parser("kel", help="export the key history of an identity")
    s.add_argument("identity")
    s.add_argument("-o", "--output")
    s.set_defaults(fn=cmd_kel)

    s = sub.add_parser("present", help="sign a presentation of your statements over a verifier's code")
    s.add_argument("--as", dest="identity", required=True)
    s.add_argument("--nonce", required=True, help="the code the verifier gave you")
    s.add_argument("files", nargs="+")
    s.add_argument("--full", action="store_true", help="include the private content (default: hidden)")
    s.add_argument("-o", "--output", default="presentation.json")
    s.set_defaults(fn=cmd_present)

    s = sub.add_parser("look", help="make or check a look/1 document")
    s.add_argument("action", choices=["make", "check"])
    s.add_argument("file", help="make: a spec (file names for pictures/fonts); check: a look/1 document")
    s.add_argument("-o", "--output", default="looks", help="make: output folder")
    s.set_defaults(fn=cmd_look)

    s = sub.add_parser("hide", help="a copy without the private content, for showing")
    s.add_argument("file")
    s.add_argument("-o", "--output")
    s.set_defaults(fn=cmd_hide)

    s = sub.add_parser("open", help="show what a .dzq file says (without trusting it)")
    s.add_argument("file")
    s.set_defaults(fn=cmd_open)

    s = sub.add_parser("verify", help="check a .dzq file or a credential bundle")
    s.add_argument("file")
    s.add_argument("--seal", help="period seal JSON")
    s.add_argument("--kel", help="a fresher copy of the issuer's key history (CESR)")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_verify)

    s = sub.add_parser("presentation", help="verify a holder-bound presentation")
    s.add_argument("file")
    s.add_argument("--nonce", default="", help="the code you gave the holder (empty: display only)")
    s.add_argument("--kel", action="append", help="a fresher key history of an issuer (repeatable)")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_presentation)

    a = p.parse_args(argv)
    try:
        return a.fn(a)
    except CliError as e:
        print("error: %s" % e, file=sys.stderr)
        return EXIT_ERROR
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        print("error: %s" % e, file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())

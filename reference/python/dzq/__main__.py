"""dzq on the command line: create an identity, sign, open, verify.

    dzq init alice                        # creates alice.id (keep it private)
    dzq types                             # what you can sign, and its fields
    dzq sign --as alice.id --type gratitude --to <AID> \\
             title="Thank you" message="For fixing my bike." category=help \\
             -o thanks.dzq
    dzq open thanks.dzq                   # what the file says (trusts nothing)
    dzq verify thanks.dzq                 # whether to believe it
    dzq hide thanks.dzq -o shown.dzq      # a copy without the private text, still valid
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
            return Identity.from_secret(json.load(f)["secret"])
    except (OSError, KeyError, ValueError, json.JSONDecodeError) as e:
        raise CliError("cannot read identity %s: %s" % (path, e)) from e


def cmd_init(a):
    path = a.name if a.name.endswith(".id") else a.name + ".id"
    if os.path.exists(path) and not a.force:
        raise CliError("%s already exists (use --force to replace it)" % path)
    me = Identity.create()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump({"aid": me.aid, "secret": me.secret_hex}, f, indent=2)
    print("created %s  (private: it holds your signing secret)" % path)
    print("your AID: %s" % me.aid)
    return EXIT_VALID


def cmd_whoami(a):
    print(_load_identity(a.identity).aid)
    return EXIT_VALID


def cmd_types(a):
    for t in types.TYPES.values():
        print("%s" % t.name)
        print("  public:   %s" % (", ".join(t.public) or "-"))
        print("  private:  %s" % ", ".join(t.private))
        if t.optional:
            print("  optional: %s (private; use --attach for a file)" % ", ".join(t.optional))
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
    try:
        st = me.sign(type=a.type, to=a.to, content=content, attachment=attachment, private=not a.all_public)
    except ValueError as e:
        raise CliError(str(e)) from e
    out = a.output or "%s.dzq" % st.said[:12]
    with open(out, "wb") as f:
        f.write(st.to_dzq())
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
    r = verify.verify_presentation(open(a.file, encoding="utf-8").read(), a.nonce)
    if a.json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    else:
        print("✓ VALID" if r["valid"] else "✗ NOT VALID: %s (%s)" % (r.get("reason"), r.get("code")))
        print("  holder     %s" % r.get("holder"))
        if r["valid"] and not a.nonce:
            print("  note: no verifier code was given, so this only shows; it does not prove freshness")
        for c in r["credentials"]:
            print("  %s %s" % ("✓" if c.get("holder_is_recipient") else "✗", c.get("said") or c.get("reason")))
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
    s.set_defaults(fn=cmd_sign)

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

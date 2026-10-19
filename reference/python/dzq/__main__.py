"""Command line: check a gratitude without any DzenQ software.

    python3 -m dzq verify thanks.dzq [--seal seal.json] [--kel issuer.kel] [--json]
    python3 -m dzq verify bundle.acdc [...]
    python3 -m dzq presentation vp.json --nonce CODE [--json]
"""

import argparse
import json
import sys

from . import archive, verify

EXIT_VALID, EXIT_INVALID, EXIT_ERROR = 0, 1, 2

WORDS = {
    "format": "not a gratitude",
    "canonical": "not in canonical form",
    "schema": "does not follow the gratitude schema",
    "said": "content was changed after signing",
    "kel": "the issuer's key log is missing or invalid",
    "no-signature": "not signed",
    "signature": "not signed by the issuer",
    "not-current": "not signed by the issuer's current key, and not sealed",
    "seal": "the period seal does not prove it",
    "archive": "not a safe .dzq archive",
    "nonce": "made for another request",
    "credential": "a gratitude is invalid or not the presenter's",
}


def _human(r):
    if r.get("valid"):
        lines = ["VALID"]
        for k in ("said", "issuer", "recipient"):
            if r.get(k):
                lines.append("  %-10s %s" % (k, r[k]))
        lines.append("  %-10s %s" % ("sealed", "yes, at issuer event %s" % r["anchored_at_sn"] if r.get("sealed")
                                     else "no (valid by the issuer's latest key you have)"))
        if r.get("redeemed_at_sn") is not None:
            lines.append("  %-10s at issuer event %s" % ("redeemed", r["redeemed_at_sn"]))
        if r.get("attachment"):
            lines.append("  %-10s %s" % ("attachment", r["attachment"]))
        if not r.get("sealed"):
            lines.append("  note: checked against the issuer key log in the file (sn %s). Load a fresh one "
                         "(--kel) to be sure the key was not rotated since." % r.get("issuer_kel_sn"))
        return "\n".join(lines)
    return "INVALID: %s\n  %s" % (WORDS.get(r.get("code"), r.get("code")), r.get("reason"))


def main(argv=None):
    p = argparse.ArgumentParser(prog="dzq", description="dzq/1.0 reference verifier")
    sub = p.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify", help="verify a .dzq file or a credential bundle")
    v.add_argument("file")
    v.add_argument("--seal", help="period seal JSON of this gratitude")
    v.add_argument("--kel", help="a fresher copy of the issuer's KEL (CESR)")
    v.add_argument("--json", action="store_true")
    vp = sub.add_parser("presentation", help="verify a holder-bound presentation")
    vp.add_argument("file")
    vp.add_argument("--nonce", default="", help="the code you gave the holder (empty: display only)")
    vp.add_argument("--json", action="store_true")
    a = p.parse_args(argv)

    try:
        if a.cmd == "verify":
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
            print(json.dumps(r, ensure_ascii=False, indent=2) if a.json else _human(r))
        else:
            r = verify.verify_presentation(open(a.file, encoding="utf-8").read(), a.nonce)
            if a.json:
                print(json.dumps(r, ensure_ascii=False, indent=2))
            else:
                head = "VALID" if r["valid"] else "INVALID: %s" % WORDS.get(r["code"], r["code"])
                print("%s\n  holder     %s" % (head, r.get("holder")))
                if r["valid"] and not a.nonce:
                    print("  note: no verifier code was given, so this only shows, it does not prove freshness")
                for c in r["credentials"]:
                    print("  - %s %s" % ("ok " if c.get("holder_is_recipient") else "BAD", c.get("said") or c.get("reason")))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        print("error: %s" % e, file=sys.stderr)
        return EXIT_ERROR
    return EXIT_VALID if r["valid"] else EXIT_INVALID


if __name__ == "__main__":
    sys.exit(main())

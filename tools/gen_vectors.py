#!/usr/bin/env python3
"""Generates the dzq/1.0 test vectors into ../vectors (reproducible: fixed
seeds, fixed dates, fixed ZIP timestamps).

    python3 tools/gen_vectors.py          # write
    python3 tools/gen_vectors.py --check  # fail if the committed vectors differ
"""

import json
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "reference", "python"))

from dzq import acdc, archive, build, cesr, conditions, merkle  # noqa: E402
from dzq.blake3 import blake3  # noqa: E402

DT = "2026-10-19T12:00:00+00:00"
NONCE = "door-7Q4M-2026"


def attrs(recipient=None, condition=None, title="Дякую", message="За допомогу з переїздом", category="help", **extra):
    a = {}
    if recipient is not None:
        a["i"] = recipient
    if condition is not None:
        a["dq"] = condition
    a.update(dt=DT, title=title, message=message, category=category)
    a.update(extra)
    return a


class Out:
    def __init__(self, base):
        self.base = base
        self.manifest = {"spec": "dzq/1.4", "credentials": [], "archives": [], "presentations": []}

    def write(self, rel, data):
        path = os.path.join(self.base, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        mode = "wb" if isinstance(data, bytes) else "w"
        with open(path, mode, **({} if mode == "wb" else {"encoding": "utf-8", "newline": ""})) as f:
            f.write(data)
        return rel

    def json(self, rel, value):
        return self.write(rel, json.dumps(value, ensure_ascii=False, indent=2) + "\n")

    def credential(self, name, description, bundle, expect, seal=None, kel=None, types=None):
        entry = {"name": name, "description": description,
                 "bundle": self.write("credentials/%s.acdc" % name, bundle)}
        if types:
            entry["types"] = list(types)
        if seal is not None:
            entry["seal"] = self.json("credentials/%s.seal.json" % name, seal)
        if kel is not None:
            entry["kel"] = self.write("credentials/%s.kel" % name, kel)
        entry["expect"] = expect
        self.manifest["credentials"].append(entry)

    def archive(self, name, description, data, expect):
        self.manifest["archives"].append({"name": name, "description": description,
                                          "file": self.write("archives/%s.dzq" % name, data),
                                          "expect": expect})

    def presentation(self, name, description, vp, nonce, expect, now=None, types=None, extensions=None):
        entry = {"name": name, "description": description,
                 "file": self.write("presentations/%s.json" % name, vp), "nonce": nonce}
        if now is not None:
            entry["now"] = now
        if types:
            entry["types"] = list(types)
        if extensions:
            entry["extensions"] = list(extensions)
        entry["expect"] = expect
        self.manifest["presentations"].append(entry)


def forge_inception(prefix, attacker):
    """An inception event that claims `prefix` but carries the attacker's keys.
    Its d and i are the victim's AID, so its SAID cannot recompute."""
    ev = {"v": "KERI10JSON000000_", "t": "icp", "d": prefix, "i": prefix, "s": "0", "kt": "1",
          "k": [attacker.current.qb64], "nt": "1", "n": [cesr.blake3_said(attacker.next.qb64)],
          "bt": "0", "b": [], "c": [], "a": []}
    ev["v"] = "KERI10JSON%06x_" % len(acdc.dumps(ev).encode())
    raw = acdc.dumps(ev)
    return raw + cesr.counter_indexed_sigs([cesr.indexed_sig_qb64(attacker.current.sign(raw), 0)])


def valid(**kw):
    e = {"valid": True, "sealed": False}
    e.update(kw)
    return e


def invalid(code):
    return {"valid": False, "code": code}


def tamper(bundle, old, new):
    assert old in bundle, old
    return bundle.replace(old, new, 1)


def generate(base):
    out = Out(base)
    alice = build.Controller("alice").incept()    # issuer
    bob = build.Controller("bob").incept()        # recipient
    carol = build.Controller("carol").incept()    # someone else
    dave = build.Controller("dave").incept()      # gets a letter to an address
    mallory = build.Controller("mallory").incept()

    # --- credentials: the core -------------------------------------------
    g1 = alice.gratitude(attrs(recipient=bob.prefix))
    b1 = alice.bundle(g1)
    out.credential("classic", "A thank-you to one AID (schema 1.0.0), not yet sealed: valid by the issuer's current key.",
                   b1, valid(said=g1["d"], issuer=alice.prefix, recipient=bob.prefix, schema=acdc.SCHEMA_GRATITUDE))

    group = "?aid=" + carol.prefix
    g2 = alice.gratitude(attrs(condition=group, title="Дякую команді", message="За вечір", category="team"))
    b2 = alice.bundle(g2)
    out.credential("condition-aid", "A thank-you to a condition (schema 2.0.0): ?aid=<Carol>.",
                   b2, valid(said=g2["d"], recipient=group, schema=acdc.SCHEMA_GRATITUDE_CONDITION))

    letter_key = blake3(b"dzq vector letter key")[:16].hex()
    ck = build.claim_key(letter_key, "email", "dave@example.org")
    letter = "?claim=" + ck.pub.hex()
    g3 = alice.gratitude(attrs(condition=letter, title="Дякую", message="За лист", category="letter"))
    b3 = alice.bundle(g3)
    out.credential("condition-claim", "A letter to an e-mail address: the condition is one claim key.",
                   b3, valid(said=g3["d"], recipient=letter))

    g5 = alice.gratitude(attrs(condition="any(%s,%s)" % (bob.prefix, carol.prefix), category="oops"))
    out.credential("condition-malformed", "A condition that does not parse (the old any(…) form): the statement verifies, but nobody can ever hold it.",
                   alice.bundle(g5), valid(recipient="any(%s,%s)" % (bob.prefix, carol.prefix)))

    att_body = "Фото з переїзду (тест)\n".encode("utf-8")
    g6 = alice.gratitude(attrs(recipient=bob.prefix, attachment={
        "d": blake3(att_body).hex(), "filename": "photo.txt", "mime_type": "text/plain", "size": len(att_body)}))
    b6 = alice.bundle(g6)
    out.credential("attachment", "A thank-you naming an attached file by its BLAKE3 digest.", b6, valid(said=g6["d"]))

    # tampering
    out.credential("tampered-message", "The message was changed after signing.",
                   tamper(b1, "За допомогу з переїздом", "За шкоду з переїздом"), invalid("said"))
    out.credential("tampered-recipient", "The recipient AID was swapped for another.",
                   tamper(b1, bob.prefix, carol.prefix), invalid("said"))
    out.credential("tampered-version", "The size in the version string is wrong.",
                   tamper(b1, g1["v"], g1["v"][:10] + "%06x_" % (int(g1["v"][10:16], 16) + 1)), invalid("said"))
    raw1 = acdc.dumps(g1)
    pretty = json.dumps(g1, ensure_ascii=False, indent=1)
    out.credential("non-canonical", "Same content, but not in the canonical serialization (whitespace).",
                   b1.replace(raw1, pretty, 1), invalid("canonical"))
    reordered = acdc.dumps({k: g1[k] for k in ("d", "v", "i", "ri", "s", "a")})
    out.credential("non-canonical-order", "Same content, fields in another order.",
                   b1.replace(raw1, reordered, 1), invalid("canonical"))
    escaped = json.dumps(g1, ensure_ascii=True, separators=(",", ":"))
    out.credential("non-canonical-escapes", "Same content, non-ASCII text escaped as \\uXXXX.",
                   b1.replace(raw1, escaped, 1), invalid("canonical"))

    wrong = acdc.saidify(dict(g1, s=acdc.SCHEMA_GRATITUDE_CONDITION))
    out.credential("schema-mismatch", "Recipient in a.i under the condition schema 2.0.0.",
                   alice.bundle(wrong), invalid("schema"))
    unknown = acdc.saidify(dict(g1, s=cesr.blake3_said("some other schema")))
    out.credential("schema-unknown", "A type SAID this reader does not know: the envelope is checked, the type is reported unknown.",
                   alice.bundle(unknown), valid(type=None, type_known=False))
    extra = dict(g1)
    extra["a"] = dict(g1["a"], mood="happy")
    try:
        acdc.saidify(extra)
        raise AssertionError("unknown field accepted")
    except acdc.AcdcError:
        pass
    a_extra = dict(g1["a"], mood="happy")
    a_extra["d"] = acdc.attribute_said(a_extra)
    ev = {"v": acdc.version_string(0), "d": cesr.SAID_PLACEHOLDER, "i": g1["i"], "ri": g1["ri"], "s": g1["s"], "a": a_extra}
    ev["v"] = acdc.version_string(len(acdc.dumps(ev).encode()))
    ev["d"] = cesr.blake3_said(acdc.dumps(ev))
    out.credential("unknown-attribute", "An attribute not in the schema (a.mood), with SAIDs recomputed.",
                   alice.bundle(ev), invalid("schema"))

    out.credential("no-signature", "The signature group is missing.",
                   raw1 + alice.kel(), invalid("no-signature"))
    out.credential("forged-signature", "Signed by another identifier's key, claiming to be the issuer.",
                   alice.bundle(g1, key=mallory.current), invalid("not-current"))
    kel_bad = alice.kel()
    sig_at = kel_bad.index("-AAB") + 6
    kel_bad = kel_bad[:sig_at] + ("A" if kel_bad[sig_at] != "A" else "B") + kel_bad[sig_at + 1:]
    out.credential("kel-bad-signature", "The issuer's inception event carries a broken signature.",
                   alice.bundle(g1, kel=kel_bad), invalid("kel"))
    out.credential("kel-of-someone-else", "The bundle carries another identifier's KEL.",
                   alice.bundle(g1, kel=mallory.kel()), invalid("kel"))

    forged_icp = forge_inception(alice.prefix, mallory)
    out.credential("kel-forged-inception", "Mallory writes an inception event for Alice's AID with Mallory's own keys "
                   "(its SAID does not recompute) and signs a thank-you 'from Alice'.",
                   alice.bundle(g1, key=mallory.current, kel=forged_icp), invalid("kel"))
    long_a = dict(g1["a"], title="Д" * 201)
    long_a["d"] = acdc.attribute_said(long_a)
    long_g = {"v": acdc.version_string(0), "d": cesr.SAID_PLACEHOLDER, "i": g1["i"], "ri": g1["ri"], "s": g1["s"], "a": long_a}
    long_g["v"] = acdc.version_string(len(acdc.dumps(long_g).encode()))
    long_g["d"] = cesr.blake3_said(acdc.dumps(long_g))
    out.credential("title-too-long", "A title of 201 characters (the schema allows 200), SAIDs recomputed.",
                   alice.bundle(long_g), invalid("schema"))
    plus = dict(g1, v=g1["v"][:10] + "+" + g1["v"][11:])
    assert g1["v"][10] == "0"
    plus_raw = acdc.dumps(dict(plus, d=cesr.SAID_PLACEHOLDER))
    plus["d"] = cesr.blake3_said(plus_raw)
    out.credential("version-plus-sign", "The version string writes the size as '+0019c' (same number, not canonical); SAID recomputed.",
                   alice.bundle(plus), invalid("said"))

    # --- extension: periods (rotation, seals) ----------------------------
    issuer = build.Controller("ivan").incept()
    t1 = issuer.gratitude(attrs(recipient=bob.prefix, message="Перша"))
    t2 = issuer.gratitude(attrs(recipient=carol.prefix, message="Друга"))
    t3 = issuer.gratitude(attrs(recipient=bob.prefix, message="Третя, не запечатана"))
    bt1, bt2, bt3 = issuer.bundle(t1), issuer.bundle(t2), issuer.bundle(t3)
    since = issuer.sn
    seals = issuer.close_period([t1["d"], t2["d"]], since=since)
    close_sn = issuer.sn
    issuer.rotate()
    fresh = issuer.kel()

    out.credential("stale-kel-offline", "Signed by the issuer's key at issuance; the bundle carries only that KEL. "
                   "Offline this verifies (the verifier does not know about the later rotation).",
                   bt3, valid(issuer_kel_sn=0))
    out.credential("rotated-unsealed", "Same thank-you, checked against the issuer's fresh KEL: it was never sealed and the key rotated, so it is void.",
                   bt3, invalid("not-current"), kel=fresh)
    out.credential("rotated-sealed", "Sealed in a period before the rotation: valid with the fresh KEL and its period seal.",
                   bt1, valid(sealed=True, anchored_at_sn=close_sn), seal=seals[t1["d"]], kel=fresh)
    out.credential("rotated-sealed-second-leaf", "The other thank-you of the same period.",
                   bt2, valid(sealed=True, anchored_at_sn=close_sn), seal=seals[t2["d"]], kel=fresh)
    out.credential("rotated-no-seal", "Sealed, but the holder did not supply the seal: it counts as unsealed.",
                   bt1, invalid("not-current"), kel=fresh)
    out.credential("seal-of-another", "The period seal of a different thank-you.",
                   bt1, invalid("seal"), seal=seals[t2["d"]], kel=fresh)
    forged_record = json.loads(seals[t1["d"]]["close"])
    forged_record["count"] = 3
    forged = {"close": json.dumps(forged_record, separators=(",", ":")), "proof": seals[t1["d"]]["proof"]}
    out.credential("seal-not-anchored", "A close record that the issuer never anchored.",
                   bt1, invalid("seal"), seal=forged, kel=fresh)

    old = build.Controller("olena").incept()
    t5 = old.gratitude(attrs(recipient=bob.prefix, message="Стара, з власним якорем"))
    bt5 = old.bundle(t5)
    old.anchor(t5["d"])
    old.rotate()
    out.credential("anchored", "An older thank-you anchored on its own (an event seal naming its SAID); still valid after rotation.",
                   bt5, valid(sealed=True, anchored_at_sn=1), kel=old.kel())

    red = build.Controller("roman").incept()
    t6 = red.gratitude(attrs(recipient=bob.prefix, message="Погашена"))
    bt6 = red.bundle(t6)
    red.redeem(t6["d"])
    out.credential("redeemed", "Valid, and redeemed by the issuer (a digest seal of the redemption record).",
                   bt6, valid(redeemed_at_sn=1), kel=red.kel())

    gone = build.Controller("zoya").incept()
    t7 = gone.gratitude(attrs(recipient=bob.prefix, message="Від видаленої особи"))
    bt7 = gone.bundle(t7)
    gone.rotate(abandon=True)
    out.credential("abandoned-issuer", "The issuer abandoned its identifier (rotation to no next key); unsealed thanks are void.",
                   bt7, invalid("not-current"), kel=gone.kel())

    # --- dzq/1.1: private content -------------------------------------------
    def salt(name):
        return cesr.encode("0A", blake3(("dzq vector salt|" + name).encode())[:16])

    def private(issuer, name, **attributes):
        return acdc.new_private_gratitude(issuer.prefix, cesr.blake3_said("registry|" + issuer.prefix),
                                          attrs(**attributes), salt=salt(name))

    def resaid(cred):
        """Recompute every SAID of a (possibly malformed) private credential, bypassing validation."""
        cred = json.loads(json.dumps(cred))
        c = cred["a"]["c"]
        if isinstance(c, dict):
            c["d"] = cesr.SAID_PLACEHOLDER
            c["d"] = cesr.blake3_said(acdc.dumps(c))
        comp = acdc.compact(cred)
        comp["a"]["d"] = cesr.SAID_PLACEHOLDER
        comp["a"]["d"] = cesr.blake3_said(acdc.dumps(comp["a"]))
        comp["d"] = cesr.SAID_PLACEHOLDER
        comp["v"] = acdc.version_string(0)
        comp["v"] = acdc.version_string(len(acdc.dumps(comp).encode()))
        comp["d"] = cesr.blake3_said(acdc.dumps(comp))
        if isinstance(c, dict):
            comp["a"]["c"] = c
        return comp

    p1 = private(alice, "p1", recipient=bob.prefix, message="За допомогу з переїздом (приватно)")
    p1_full = alice.bundle(p1)
    p1_compact = alice.bundle(acdc.compact(p1))
    assert acdc.compact(p1)["d"] == p1["d"]
    out.credential("private-full", "dzq/1.1: title and message in the salted block, shown. Signature covers the compact form.",
                   p1_full, valid(said=p1["d"], schema=acdc.SCHEMA_GRATITUDE_PRIVATE, content="shown"))
    out.credential("private-compact", "The same statement with the block replaced by its SAID: same id, same signature.",
                   p1_compact, valid(said=p1["d"], content="hidden"))
    out.credential("private-edited-message", "The full form with the message changed after signing.",
                   tamper(p1_full, "(приватно)", "(змінено!)"), invalid("said"))
    other = cesr.blake3_said("another content block")
    out.credential("private-wrong-digest", "A compact form whose content SAID was swapped for another.",
                   tamper(p1_compact, p1["a"]["c"]["d"], other), invalid("said"))
    no_salt = json.loads(json.dumps(p1))
    del no_salt["a"]["c"]["u"]
    out.credential("private-no-salt", "A content block without a salt (SAIDs recomputed): guessable, refused.",
                   alice.bundle(resaid(no_salt)), invalid("schema"))
    short_salt = json.loads(json.dumps(p1))
    short_salt["a"]["c"]["u"] = "0Aabc"
    out.credential("private-bad-salt", "A salt that is not 128 bits (SAIDs recomputed).",
                   alice.bundle(resaid(short_salt)), invalid("schema"))
    leaked = json.loads(json.dumps(p1))
    leaked["a"] = {"d": "", "i": bob.prefix, "dt": DT, "title": "Відкритий заголовок", "category": "help", "c": p1["a"]["c"]}
    out.credential("private-title-outside", "A private-schema statement with the title outside the block (SAIDs recomputed).",
                   alice.bundle(resaid(leaked)), invalid("schema"))
    p2 = private(alice, "p2", condition=letter, message="Лист на адресу (приватно)", category="letter")
    out.credential("private-condition", "dzq/1.1 to a condition (schema 2.1.0), full form.",
                   alice.bundle(p2), valid(said=p2["d"], schema=acdc.SCHEMA_GRATITUDE_PRIVATE_CONDITION, content="shown"))

    # --- archives ---------------------------------------------------------
    meta = {"id": g1["d"], "title": g1["a"]["title"], "message": g1["a"]["message"], "issuedAt": DT,
            "issuer_aid": alice.prefix, "recipient_aid": bob.prefix}
    out.archive("minimal", "Only credential.acdc.", archive.zip_entries([("credential.acdc", b1.encode())]),
                valid(said=g1["d"], attachment=None))
    out.archive("with-metadata", "credential.acdc and metadata.json (display only).",
                archive.make_dzq(b1, metadata=meta), valid(said=g1["d"]))
    out.archive("legacy-signatures-json", "Written by DzenQ before dzq/1.0: an empty signatures.json, ignored.",
                archive.zip_entries([("metadata.json", json.dumps(meta).encode()), ("credential.acdc", b1.encode()),
                                     ("signatures.json", b"{}")]), valid(said=g1["d"]))
    lying = dict(meta, message="Зовсім інший текст")
    out.archive("lying-metadata", "metadata.json disagrees with the credential; metadata is never trusted.",
                archive.make_dzq(b1, metadata=lying), valid(said=g1["d"]))
    out.archive("attachment", "With the attached file the credential names.",
                archive.make_dzq(b6, attachment=("photo.txt", att_body)), valid(attachment="ok"))
    out.archive("attachment-swapped", "The attached file was replaced; the credential is valid, the file is not its.",
                archive.make_dzq(b6, attachment=("photo.txt", b"something else")), valid(attachment="mismatch"))
    out.archive("attachment-missing", "The credential names a file the archive lacks.",
                archive.make_dzq(b6), valid(attachment="missing"))
    out.archive("tampered", "A .dzq around a tampered credential.",
                archive.make_dzq(tamper(b1, "За допомогу", "За шкоду!!")), invalid("said"))
    out.archive("path-traversal", "An entry that escapes the archive.",
                archive.zip_entries([("credential.acdc", b1.encode()), ("assets/../../evil.sh", b"x")]),
                {"valid": False, "code": "archive"})
    out.archive("unexpected-entry", "An entry dzq/1.0 does not define.",
                archive.zip_entries([("credential.acdc", b1.encode()), ("run.exe", b"x")]),
                {"valid": False, "code": "archive"})
    out.archive("no-credential", "No credential.acdc.",
                archive.zip_entries([("metadata.json", json.dumps(meta).encode())]),
                {"valid": False, "code": "archive"})
    out.archive("too-many-entries", "More than 20 entries.",
                archive.zip_entries([("credential.acdc", b1.encode())] + [("assets/f%02d.txt" % i, b"x") for i in range(20)]),
                {"valid": False, "code": "archive"})
    out.archive("not-zip", "Not a ZIP file at all.", b1.encode(), {"valid": False, "code": "archive"})

    p_att = acdc.new_private_gratitude(alice.prefix, cesr.blake3_said("registry|" + alice.prefix), attrs(
        recipient=bob.prefix, attachment={"d": blake3(att_body).hex(), "filename": "photo.txt",
                                          "mime_type": "text/plain", "size": len(att_body)}), salt=salt("p-att"))
    out.archive("private-attachment", "dzq/1.1 full form with its attachment: the file is checked against the private block.",
                archive.make_dzq(alice.bundle(p_att), attachment=("photo.txt", att_body)), valid(attachment="ok", content="shown"))
    out.archive("private-compact", "dzq/1.1 compact copy for showing: no text, no attachment, still valid.",
                archive.make_dzq(alice.bundle(acdc.compact(p_att))), valid(attachment=None, content="hidden"))
    # --- presentations ----------------------------------------------------
    def vp(holder, creds, nonce=NONCE, **kw):
        return build.presentation(holder, creds, nonce, DT, **kw)

    out.presentation("classic", "Bob proves he holds a thank-you addressed to him.",
                     vp(bob, [b1]), NONCE, {"valid": True, "holder": bob.prefix})
    out.presentation("wrong-nonce", "The same proof, made for another request.",
                     vp(bob, [b1], nonce="door-OTHER-0000"), NONCE, {"valid": False, "code": "nonce"})
    out.presentation("display-only", "No verifier code was asked for: shown, but proves no freshness.",
                     vp(bob, [b1], nonce="door-OTHER-0000"), "", {"valid": True, "holder": bob.prefix})
    out.presentation("not-the-recipient", "Carol presents Bob's thank-you as hers.",
                     vp(carol, [b1]), NONCE, {"valid": False, "code": "credential"})
    out.presentation("condition-aid-holder", "Carol holds the thank-you to ?aid=<Carol>.",
                     vp(carol, [b2]), NONCE, {"valid": True, "holder": carol.prefix})
    proof = build.claim_proof(ck, g3["d"], dave.prefix)
    out.presentation("letter-claimed", "Dave got the letter key through his e-mail and claims the letter.",
                     vp(dave, [b3], claims=[proof]), NONCE, {"valid": True, "holder": dave.prefix})
    out.presentation("letter-no-claim", "Dave presents the letter without the claim.",
                     vp(dave, [b3]), NONCE, {"valid": False, "code": "credential"})
    stolen = build.claim_proof(ck, g3["d"], mallory.prefix)
    out.presentation("letter-claim-for-another", "Dave presents a claim made out to another AID.",
                     vp(dave, [b3], claims=[stolen]), NONCE, {"valid": False, "code": "credential"})
    bad_proof = dict(proof, signature=proof["signature"][:-2] + ("00" if proof["signature"][-2:] != "00" else "11"))
    out.presentation("letter-claim-bad-signature", "The claim signature does not verify.",
                     vp(dave, [b3], claims=[bad_proof]), NONCE, {"valid": False, "code": "credential"})
    erin = build.Controller("erin").incept()
    out.presentation("malformed-condition", "Nobody holds a thank-you whose condition does not parse.",
                     vp(bob, [alice.bundle(g5)]), NONCE, {"valid": False, "code": "credential"})
    signed = json.loads(vp(bob, [b1]))
    signed["payload"] = signed["payload"].replace(NONCE, "door-7Q4M-2027")
    out.presentation("tampered-payload", "The payload was edited after the holder signed it.",
                     json.dumps(signed, ensure_ascii=False, separators=(",", ":")), "door-7Q4M-2027",
                     {"valid": False, "code": "signature"})
    sealed_bundle = issuer.bundle(t1, key=build.Key.named("ivan/0"), kel=fresh)
    out.presentation("sealed-after-rotation", "Bob presents a sealed thank-you whose issuer rotated since; the bundle carries the fresh KEL and the presentation the seal.",
                     vp(bob, [sealed_bundle], seals={t1["d"]: seals[t1["d"]]}), NONCE,
                     {"valid": True, "holder": bob.prefix})
    out.presentation("unsealed-after-rotation", "The same issuer's unsealed thank-you, with the fresh KEL: void.",
                     vp(bob, [issuer.bundle(t3, key=build.Key.named("ivan/0"), kel=fresh)]), NONCE,
                     {"valid": False, "code": "credential"})

    fake_bob = build.Controller("mallory-as-bob")
    fake_bob.prefix = bob.prefix
    fake_bob.events = [forge_inception(bob.prefix, mallory)]
    fake_bob.current = mallory.current
    out.presentation("forged-holder-kel", "Mallory presents Bob's thank-you with a forged inception for Bob's AID carrying Mallory's key.",
                     vp(fake_bob, [b1]), NONCE, {"valid": False, "code": "kel"})
    legacy = alice.gratitude(attrs(recipient="any(%s,%s)" % (bob.prefix, mallory.prefix), message="Умова в a.i"))
    out.presentation("condition-in-a-i", "A schema 1.0.0 thank-you whose a.i holds a condition (pre-1.0 test letters); "
                     "under dzq/1.0 a.i is one AID, so Mallory does not hold it.",
                     vp(mallory, [alice.bundle(legacy)]), NONCE, {"valid": False, "code": "credential"})
    no_dt = json.loads(json.loads(vp(bob, [b1]))["payload"])
    del no_dt["dt"]
    no_dt_text = acdc.dumps(no_dt)
    out.presentation("missing-dt", "A presentation payload without dt.",
                     acdc.dumps({"payload": no_dt_text, "signature": bob.sign_payload(no_dt_text)}), NONCE,
                     {"valid": False, "code": "format"})

    out.presentation("private-compact-at-door", "Bob shows a dzq/1.1 thank-you to a door without its text.",
                     vp(bob, [p1_compact]), NONCE, {"valid": True, "holder": bob.prefix})
    out.presentation("private-letter-claimed-compact", "Dave claims a dzq/1.1 letter and shows it without its text.",
                     vp(dave, [alice.bundle(acdc.compact(p2))], claims=[build.claim_proof(ck, p2["d"], dave.prefix)]),
                     NONCE, {"valid": True, "holder": dave.prefix})

    # --- conditions: lists, record conditions ----------------------------
    def typed(issuer, name, **fields):
        return acdc.new_typed(issuer.prefix, cesr.blake3_said("registry|" + issuer.prefix), types_.GRATITUDE,
                              dict({"dt": DT, "category": "help", "title": "Дякую", "message": name}, **fields),
                              salt=salt(name))
    from dzq import types as types_
    k_a = build.claim_key(letter_key, "email", "erin@example.org")
    k_b = build.claim_key(letter_key, "phone", "+380501234567")
    two_claims = typed(alice, "two-claims", req=["?claim=" + k_a.pub.hex(), "?claim=" + k_b.pub.hex()])
    out.presentation("list-of-two-claims", "a.req is a list: either claim is enough. Erin claims one of them.",
                     vp(erin, [alice.bundle(two_claims)], claims=[build.claim_proof(k_b, two_claims["d"], erin.prefix)]),
                     NONCE, {"valid": True, "holder": erin.prefix})
    group_list = typed(alice, "group-list", req=["?aid=" + bob.prefix, "?aid=" + carol.prefix])
    out.credential("condition-list", "a.req as a list of conditions: Bob or Carol.",
                   alice.bundle(group_list), valid(recipient=["?aid=" + bob.prefix, "?aid=" + carol.prefix]))
    out.presentation("condition-list-member", "Carol holds the thank-you to [?aid=<Bob>, ?aid=<Carol>].",
                     vp(carol, [alice.bundle(group_list)]), NONCE, {"valid": True, "holder": carol.prefix})
    unknown_key = typed(alice, "unknown-key", req=["?txn=6H24-KE7X", "?aid=" + bob.prefix])
    out.presentation("condition-unknown-key", "Bob meets [?txn=…, ?aid=<Bob>] through his AID; the unknown condition is never met.",
                     vp(bob, [alice.bundle(unknown_key)]), NONCE, {"valid": True, "holder": bob.prefix})
    for name, bad in [("condition-empty-list", []), ("condition-not-strings", [1, 2])]:
        g = typed(alice, name, req=["?aid=" + bob.prefix])
        g["a"]["req"] = bad
        out.credential(name, "a.req must be a string or a non-empty list of strings (SAIDs recomputed).",
                       alice.bundle(resaid(g)), invalid("schema"))

    # --- dzq/1.2: open types ---------------------------------------------
    from dzq import types as types_
    from dzq.typedoc import TypeDoc, make_type
    from dzq import promises as promise_ext
    GRAT = types_.GRATITUDE

    def stmt(issuer, doc, name, **fields):
        return acdc.new_typed(issuer.prefix, cesr.blake3_said("registry|" + issuer.prefix), doc,
                              dict({"dt": DT}, **fields), salt=salt(name))

    def type_file(doc):
        return out.write("types/%s.json" % doc.said, doc.text)

    g12 = stmt(alice, GRAT, "g12-plain", i=bob.prefix, category="help", title="Дякую", message="Тип 1.2")
    out.credential("gratitude-1.2", "dzq:gratitude 1.2.0, the built-in type document: to one AID, private block.",
                   alice.bundle(g12), valid(said=g12["d"], schema=acdc.SCHEMA_GRATITUDE_12, type="dzq:gratitude",
                                            type_known=True, content="shown"))
    g12c = stmt(alice, GRAT, "g12-cond", req=["?aid=" + bob.prefix, "?aid=" + carol.prefix], category="help",
                title="Дякую", message="Будь-кому з двох")
    out.credential("gratitude-1.2-condition", "The same type to a condition: one type document covers both (a.i or a.req).",
                   alice.bundle(g12c), valid(type="dzq:gratitude", content="shown"))
    out.credential("gratitude-1.2-compact", "Compact form of gratitude-1.2: same SAID, same signature.",
                   alice.bundle(acdc.compact(g12)), valid(said=g12["d"], content="hidden"))
    no_msg = json.loads(json.dumps(g12))
    del no_msg["a"]["c"]["message"]
    out.credential("gratitude-1.2-missing-field", "A required private field is missing (SAIDs recomputed): the known type refuses it.",
                   alice.bundle(resaid(no_msg)), invalid("schema"))
    long_cat = json.loads(json.dumps(g12))
    long_cat["a"]["category"] = "x" * 65
    out.credential("gratitude-1.2-too-long", "A public field longer than the type's max (SAIDs recomputed).",
                   alice.bundle(resaid(long_cat)), invalid("schema"))

    # The other base types: ordinary type documents every reader knows.
    sorry = stmt(alice, types_.APOLOGY, "sorry", i=bob.prefix, title="Вибач", message="Що запізнилась")
    out.credential("apology", "dzq:apology: nothing public but the envelope.",
                   alice.bundle(sorry), valid(said=sorry["d"], type="dzq:apology", type_known=True, content="shown"))
    out.credential("apology-compact", "The same apology, compact: only who, to whom and when are visible.",
                   alice.bundle(acdc.compact(sorry)), valid(said=sorry["d"], content="hidden"))
    with_cat = json.loads(json.dumps(sorry))
    with_cat["a"] = {"d": sorry["a"]["d"], "i": sorry["a"]["i"], "dt": DT, "category": "late", "c": sorry["a"]["c"]}
    out.credential("apology-extra-field", "An apology with a public category its type does not have (SAIDs recomputed).",
                   alice.bundle(resaid(with_cat)), invalid("schema"))
    vow = stmt(alice, types_.PROMISE, "vow", i=bob.prefix, until="2027-01-01T00:00:00+00:00", what="Полагодити велосипед")
    out.credential("promise-to-one", "dzq:promise to one AID.", alice.bundle(vow), valid(type="dzq:promise"))

    # A type anyone can define: a notice-board post.
    with open(os.path.join(ROOT, "examples", "types", "board-post.json"), encoding="utf-8") as f:
        post_text = f.read()
    POST = TypeDoc(post_text)
    post_said = POST.said
    post_file = type_file(POST)
    post = stmt(carol, POST, "post", req=["?aid=" + bob.prefix, "?aid=" + dave.prefix], area="Podil",
                text="Віддам дитячий велосипед")
    out.credential("custom-type-unknown", "A statement of a type this reader does not know: envelope, SAIDs and signature "
                   "are checked; the result says the type is unknown.",
                   carol.bundle(post), valid(said=post["d"], schema=post_said, type=None, type_known=False, content="shown"))
    out.credential("custom-type-known", "The same statement, with the type document given to the reader.",
                   carol.bundle(post), valid(said=post["d"], type="acme:board-post", type_known=True), types=[post_file])
    out.credential("custom-type-compact", "The same statement, compact: the text is hidden, the area stays public.",
                   carol.bundle(acdc.compact(post)), valid(said=post["d"], content="hidden", type="acme:board-post"),
                   types=[post_file])
    no_area = json.loads(json.dumps(post))
    del no_area["a"]["area"]
    out.credential("custom-type-breaks-type-unknown", "Missing a required field of its type, read without the type: "
                   "still a valid envelope (fields are not checked).",
                   carol.bundle(resaid(no_area)), valid(type_known=False))
    out.credential("custom-type-breaks-type-known", "The same, read with the type document: refused.",
                   carol.bundle(resaid(no_area)), invalid("schema"), types=[post_file])
    out.archive("custom-type-carried", "A .dzq that carries its type document as types/<SAID>.json: any reader can check the fields.",
                archive.make_dzq(carol.bundle(post), type_doc=POST), valid(type="acme:board-post", type_known=True))
    out.archive("custom-type-carried-tampered", "The carried type document was edited: it is ignored, the statement is valid, type unknown.",
                archive.zip_entries([(archive.CREDENTIAL, carol.bundle(post).encode()),
                                     ("types/%s.json" % post_said, post_text.replace("Board post", "Board p0st").encode())]),
                valid(type_known=False))
    fake_said, fake_text = make_type("dzq:gratitude", "9.0.0", public=[], private=[{"name": "text"}])
    fake = TypeDoc(fake_text)
    fake_st = stmt(carol, fake, "fake", i=bob.prefix, text="Я теж gratitude")
    out.archive("reserved-source-carried", "A carried type document claims the reserved dzq: source: ignored, type unknown.",
                archive.make_dzq(carol.bundle(fake_st), type_doc=fake), valid(type_known=False))
    float_said = json.loads(json.dumps(post))
    float_said["a"]["area"] = 1.5
    out.credential("envelope-float", "A float in a field (SAIDs recomputed): not allowed in any type.",
                   carol.bundle(resaid(float_said)), invalid("schema"))
    reserved = json.loads(json.dumps(post))
    reserved["a"] = {k: reserved["a"][k] for k in ("d", "req", "dt")}
    reserved["a"]["u"] = "x"
    reserved["a"]["c"] = post["a"]["c"]
    out.credential("envelope-reserved-name", "A public field named u (reserved).",
                   carol.bundle(resaid(reserved)), invalid("schema"))
    c_first = json.loads(json.dumps(post))
    c_first["a"] = {"d": post["a"]["d"], "req": post["a"]["req"], "dt": DT, "c": post["a"]["c"], "area": "Podil"}
    out.credential("envelope-c-not-last", "a.c before a public field.",
                   carol.bundle(resaid(c_first)), invalid("schema"))
    no_dt = json.loads(json.dumps(post))
    no_dt["a"] = {k: v for k, v in post["a"].items() if k != "dt"}
    out.credential("envelope-no-dt", "No a.dt.", carol.bundle(resaid(no_dt)), invalid("schema"))
    big = stmt(carol, POST, "big", i=bob.prefix, area="Podil", text="x")
    big["a"]["c"]["text"] = "я" * 140000
    out.credential("envelope-too-large", "A statement over 256 KB.", carol.bundle(resaid(big)), invalid("format"))

    # re: the statement this one answers (a hint, inside the private block).
    reply = stmt(bob, GRAT, "reply", i=alice.prefix, category="thanks", title="Навзаєм",
                 message="Дякую за подяку", re=g12["d"])
    out.credential("re", "A gratitude that answers another statement (re = its SAID).",
                   bob.bundle(reply), valid(re=g12["d"], content="shown"))
    out.credential("re-compact", "Compact: the link is hidden with the text.",
                   bob.bundle(acdc.compact(reply)), valid(content="hidden"))
    bad_re = json.loads(json.dumps(reply))
    bad_re["a"]["c"]["re"] = "not a said"
    out.credential("re-not-a-said", "re is not a SAID (SAIDs recomputed).", bob.bundle(resaid(bad_re)), invalid("schema"))

    # look: a pointer <source>:<id> (the look/1 document is an optional extension).
    from dzq import look as look_
    png = bytes.fromhex("89504e470d0a1a0a0000000d4948445200000001000000010802000000907753de"
                        "0000000c4944415408d763f8cfc000000301010018dd8db00000000049454e44ae426082")
    png_said = cesr.blake3_said(png)
    look_said, look_text = look_.make_document({"name": "Gold", "layout": "card",
                                                "background": {"color": "#B8860B", "image": png_said}})
    gl = stmt(alice, GRAT, "g12", i=bob.prefix, category="help", title="Дякую",
              message="З бланком", look="dzenq:" + look_said)
    out.credential("look-full", "A gratitude naming a look (dzenq:<SAID>), full form.",
                   alice.bundle(gl), valid(said=gl["d"], schema=acdc.SCHEMA_GRATITUDE_12, content="shown"))
    out.credential("look-compact", "The same, compact: the look is hidden with the text.",
                   alice.bundle(acdc.compact(gl)), valid(content="hidden"))
    out.credential("look-changed", "The look was swapped for another after signing.",
                   tamper(alice.bundle(gl), "dzenq:" + look_said, "dzenq:" + cesr.blake3_said("other look")), invalid("said"))
    bad_look = json.loads(json.dumps(gl))
    bad_look["a"]["c"]["look"] = "gold"
    out.credential("look-without-source", "A look with no source (SAIDs recomputed): refused.",
                   alice.bundle(resaid(bad_look)), invalid("schema"))
    named = stmt(alice, GRAT, "g12n", i=bob.prefix, category="help", title="Дякую",
                 message="Каталожний бланк", look="dzenq:gold")
    out.archive("look-carried", "A gratitude with its look/1 document and picture inside the .dzq (extension: looks).",
                archive.make_dzq(alice.bundle(gl), look=(look_said, look_text, {png_said: png})),
                valid(look="ok", content="shown"))
    out.archive("look-named-only", "A catalogue look, named but not carried.",
                archive.make_dzq(alice.bundle(named)), valid(look="named"))
    out.archive("look-document-tampered", "The carried look document was edited: the statement is valid, the look is not used.",
                archive.make_dzq(alice.bundle(gl), look=(look_said, look_text.replace("#B8860B", "#000000"), {png_said: png})),
                {"valid": True, "look": "invalid: the look's SAID does not match its content"})
    gif = b"GIF89a\x01\x00\x01\x00\x00\x00\x00;"
    gif_said = cesr.blake3_said(gif)
    gif_look_said, gif_look_text = look_.make_document({"name": "Gif", "background": {"image": gif_said}})
    g12g = stmt(alice, GRAT, "g12g", i=bob.prefix, category="help", title="Дякую",
                message="GIF", look="local:" + gif_look_said)
    out.archive("look-forbidden-file", "A carried look uses a GIF: not an allowed file type.",
                archive.make_dzq(alice.bundle(g12g), look=(gif_look_said, gif_look_text, {gif_said: gif})),
                {"valid": True, "look": "invalid: images must be PNG, JPEG or WebP"})

    # --- record conditions (SPEC §4) and the promises extension ------------
    # Record conditions are core: a presentation proves them with the
    # statements it shows. "promise" in expect is the promises extension's
    # verdict (usable, or why not); cases marked "extensions" need it.
    PROMISE = types_.PROMISE
    dad = build.Controller("dad").incept()
    marko = build.Controller("marko").incept()
    sofia = build.Controller("sofia").incept()
    nb = build.Controller("neighbour").incept()
    mom = build.Controller("mom").incept()
    room = "cleaned the room"

    def want(who, type_="dzq:gratitude", count=1, also=(), **q):
        froms = [who] + list(also)
        pairs = [("from", w.prefix) for w in froms] + list(q.items())
        if count != 1:
            pairs.append(("count", str(count)))
        return conditions.encode(type_, pairs)

    def thanks(frm, to, name, category=room, dt=DT):
        g = acdc.new_typed(frm.prefix, cesr.blake3_said("registry|" + frm.prefix), GRAT,
                           {"i": to.prefix, "dt": dt, "category": category, "title": "Дякую", "message": name},
                           salt=salt(name))
        return frm.bundle(acdc.compact(g))

    cert_req = [want(dad, to=marko.prefix, category=room, count=3), want(dad, to=sofia.prefix, category=room, count=3)]
    cert = stmt(dad, PROMISE, "cert", req=cert_req, until="2027-06-01T00:00:00+00:00",
                what="Поїздка в гори", ask="Приберіть кімнату тричі", payload="Квитки: код 7Q4M")
    cert_b = dad.bundle(acdc.compact(cert))
    out.credential("promise", "A dzq:promise whose condition asks for three 'cleaned the room' thank-yous from Dad, to Marko or to Sofia.",
                   dad.bundle(cert), valid(said=cert["d"], type="dzq:promise", content="shown"))
    out.credential("promise-compact", "The same promise, compact: what, ask and payload are hidden; until and req stay public.",
                   dad.bundle(acdc.compact(cert)), valid(said=cert["d"], content="hidden"))
    to_one = stmt(dad, PROMISE, "cert1", i=marko.prefix, what="Кава")
    t1, t2, t3 = (thanks(dad, marko, "room %d" % i) for i in (1, 2, 3))
    NOW = "2026-11-01T00:00:00+00:00"

    def pv(name, description, holder, bundles, want_, now=NOW, types=None):
        out.presentation(name, description, build.presentation(holder, bundles, NONCE, DT), NONCE,
                         {"valid": want_ == "usable", "promise": want_}, types=types,
                         now=now, extensions=["promises"])

    pv("promise-earned", "Marko shows the promise with three thank-yous from Dad (all compact).",
       marko, [cert_b, t1, t2, t3], "usable")
    pv("promise-too-few", "Only two of the three thank-yous.", marko, [cert_b, t1, t2], "not-earned")
    pv("promise-same-thanks-twice", "The same thank-you three times counts once.", marko, [cert_b, t1, t1, t1], "not-earned")
    wrong_cat = [thanks(dad, marko, "help %d" % i, category="help") for i in (1, 2)]
    pv("promise-wrong-category", "Three thank-yous, but two are in another category.", marko, [cert_b, t1] + wrong_cat, "not-earned")
    nb_thanks = [thanks(nb, marko, "nb %d" % i) for i in (1, 2)]
    pv("promise-wrong-issuer", "Two of the thank-yous come from a neighbour, not from Dad.", marko, [cert_b, t1] + nb_thanks, "not-earned")
    pv("promise-not-a-holder", "Erin has three thank-yous from Dad, but the condition asks for ones to Marko or Sofia.",
       erin, [cert_b] + [thanks(dad, erin, "e%d" % i) for i in (1, 2, 3)], "not-earned")
    pv("promise-expired", "Earned, but shown after 'until'.", marko, [cert_b, t1, t2, t3], "expired",
       now="2027-07-01T00:00:00+00:00")
    either = stmt(dad, PROMISE, "either", req=[want(dad, category=room, count=3), want(mom, count=5)], what="Піца")
    either_b = dad.bundle(acdc.compact(either))
    mom5 = [thanks(mom, marko, "mom %d" % i, category="helped with dinner") for i in range(1, 6)]
    pv("promise-either-condition", "Three from Dad for the room, or five from Mom for anything: Marko has five from Mom.",
       marko, [either_b] + mom5, "usable")
    pv("promise-counts-do-not-add-up", "Two from Dad and four from Mom: each condition counts on its own.",
       marko, [either_b, t1, t2] + mom5[:4], "not-earned")
    family = stmt(dad, PROMISE, "family", req=want(mom, also=[dad], count=5), what="Зоопарк")
    family_b = dad.bundle(acdc.compact(family))
    pv("promise-sum-two-issuers", "from=<Mom>&from=<Dad>&count=5: two from Dad and three from Mom add up.",
       marko, [family_b, t1, t2] + mom5[:3], "usable")
    pv("promise-sum-too-few", "Four of five in total.", marko, [family_b, t1] + mom5[:3], "not-earned")
    cats = stmt(dad, PROMISE, "cats", req=conditions.encode("dzq:gratitude", [("from", dad.prefix), ("category", room),
                                                                              ("category", "help"), ("count", "3")]),
                what="Кіно")
    pv("promise-any-of-two-categories", "category=…&category=help: Dad's room or help thank-yous, three together.",
       marko, [dad.bundle(acdc.compact(cats)), t1] + wrong_cat, "usable")
    any_cert = stmt(dad, PROMISE, "any", req=want(dad, count=2), what="Морозиво")
    any_b = dad.bundle(acdc.compact(any_cert))
    pv("promise-any-gratitude", "dzq:gratitude?from=<Dad>&count=2: two thank-yous from Dad, any fields.",
       marko, [any_b, t1] + wrong_cat[:1], "usable")
    sorry_from_dad = dad.bundle(acdc.compact(stmt(dad, types_.APOLOGY, "dad-sorry", i=marko.prefix,
                                                  title="Вибач", message="Що накричав")))
    pv("promise-other-type-does-not-count", "A condition counts only its type: an apology from Dad is not a gratitude.",
       marko, [any_b, t1, sorry_from_dad], "not-earned")
    sorries = [dad.bundle(acdc.compact(stmt(dad, types_.APOLOGY, "sorry %d" % k, i=marko.prefix,
                                            title="Вибач", message="Раз %d" % k))) for k in (1, 2)]
    lunch = stmt(dad, PROMISE, "lunch", req=want(dad, "dzq:apology", count=2), what="Обід")
    pv("promise-earned-with-apologies", "Any type can be asked for: a lunch for two apologies from Dad.",
       marko, [dad.bundle(acdc.compact(lunch))] + sorries, "usable")
    like_said, like_text = make_type("dzenq:like", "1.0.0", public=[], private=[], title="Like")
    LIKE = TypeDoc(like_text)
    like = dad.bundle(acdc.compact(stmt(dad, LIKE, "like 1", i=marko.prefix)))
    like_file = type_file(LIKE)
    pv("promise-like-is-not-a-gratitude", "An app's own type (dzenq:like) does not count as dzq:gratitude.",
       marko, [any_b, t1, like], "not-earned", types=[like_file])
    likes_cert = stmt(dad, PROMISE, "likes", req=want(dad, "dzenq:like"), what="Наліпка")
    pv("promise-earned-with-likes", "The app's type counts when asked for: dzenq:like?from=<Dad>.",
       marko, [dad.bundle(acdc.compact(likes_cert)), like], "usable", types=[like_file])
    by_said = stmt(dad, PROMISE, "by-said", req="%s?from=%s" % (LIKE.said, dad.prefix), what="Наліпка")
    pv("promise-type-by-said", "A type can be named by its SAID: works even for a reader that does not know it.",
       marko, [dad.bundle(acdc.compact(by_said)), like], "usable")
    since_cert = stmt(dad, PROMISE, "since", req=want(dad, category=room, since="2026-10-20T00:00:00Z"), what="Морозиво")
    pv("promise-before-since", "The only thank-you is dated before the condition's 'since'.",
       marko, [dad.bundle(acdc.compact(since_cert)), t1], "not-earned")
    self_req = want(marko, category="no smoking", count=2)
    self_thanks = [thanks(marko, marko, "day %d" % i, category="no smoking") for i in (1, 2)]
    dads_cert = stmt(dad, PROMISE, "dads", req=self_req, what="Велосипед")
    pv("promise-self-thanks-elsewhere", "Marko's thank-yous to himself do not count toward Dad's promise.",
       marko, [dad.bundle(acdc.compact(dads_cert))] + self_thanks, "not-earned")
    own = stmt(marko, PROMISE, "own", req=self_req, what="Новий светр")
    pv("promise-self-promise", "Marko's promise to himself, earned with his own thank-yous.",
       marko, [marko.bundle(acdc.compact(own))] + self_thanks, "usable")
    only_certs = stmt(dad, PROMISE, "oc", req=want(dad, category=room), what="Чай")
    pv("promise-is-not-a-thank-you", "A promise never counts as a thank-you: two promises, no gratitude.",
       marko, [dad.bundle(acdc.compact(only_certs)), dad.bundle(acdc.compact(to_one))], "not-earned")
    # Thank-yous sent to an e-mail address, claimed later, count too.
    lk = blake3(b"dzq vector letter key, promise")[:16].hex()
    mail = build.claim_key(lk, "email", "marko@example.org")
    mailed = [stmt(dad, GRAT, "mailed %d" % k, req="?claim=" + mail.pub.hex(), category=room,
                   title="Дякую", message="Лист %d" % k) for k in (1, 2, 3)]
    mail_proofs = [build.claim_proof(mail, m["d"], marko.prefix) for m in mailed]
    room3 = stmt(dad, PROMISE, "room3", req=want(dad, category=room, count=3), what="Кіно")
    room3_b = dad.bundle(acdc.compact(room3))
    mailed_b = [dad.bundle(acdc.compact(m)) for m in mailed]
    out.presentation("promise-earned-with-claimed-letters",
                     "Dad thanked Marko by e-mail three times (?claim=); Marko claimed them later and earns the promise.",
                     build.presentation(marko, [room3_b] + mailed_b, NONCE, DT, claims=mail_proofs), NONCE,
                     {"valid": True, "promise": "usable"}, now=NOW, extensions=["promises"])
    out.presentation("promise-letters-without-claims",
                     "The same letters without the claim proofs: they are not shown to be Marko's, so they do not count.",
                     build.presentation(marko, [room3_b] + mailed_b, NONCE, DT), NONCE,
                     {"valid": False, "promise": "not-earned"}, now=NOW, extensions=["promises"])
    closer = build.Controller("closer").incept()
    closing = stmt(closer, PROMISE, "closing", i=marko.prefix, what="Кіно")
    closer.interact([{"d": promise_ext.close_said(closing["d"])}])
    pv("promise-closed", "Marko shows a promise the issuer has closed (a close digest in its KEL).",
       marko, [closer.bundle(acdc.compact(closing))], "closed")
    out.presentation("record-condition-core", "Without the promises extension: Marko holds the promise (the record condition is core).",
                     build.presentation(marko, [cert_b, t1, t2, t3], NONCE, DT), NONCE,
                     {"valid": True, "holder": marko.prefix})
    out.presentation("record-condition-core-not-met", "Without the extension: two thank-yous are not enough, Marko does not hold it.",
                     build.presentation(marko, [cert_b, t1, t2], NONCE, DT), NONCE,
                     {"valid": False, "code": "credential"})

    # --- conditions (a.req) -----------------------------------------------
    A = "a" * 64
    AID1, AID2 = alice.prefix, bob.prefix
    conds = []

    def cond(text, parsed, note=""):
        c = {"condition": text, "parses": parsed is not None}
        if parsed is not None:
            c["parsed"] = parsed
        if note:
            c["note"] = note
        conds.append(c)

    G = "dzq:gratitude"
    cond("?aid=" + AID1, {"aid": [AID1]}, "the holder is this AID")
    cond("?aid=%s&aid=%s" % (AID1, AID2), {"aid": [AID1, AID2]}, "a repeated key: any of its values")
    cond("?claim=" + A.upper(), {"claim": [A]}, "claim keys are hex, compared in lower case")
    cond(G + "?from=" + AID1, {"type": G, "from": [AID1], "count": 1}, "one thank-you from AID1")
    cond(G + "?from=%s&category=help&count=3" % AID1,
         {"type": G, "from": [AID1], "fields": {"category": ["help"]}, "count": 3})
    cond(G + "?count=3&category=help&from=%s" % AID1,
         {"type": G, "from": [AID1], "fields": {"category": ["help"]}, "count": 3}, "keys in any order")
    cond(G + "?from=%s&from=%s&count=5" % (AID1, AID2), {"type": G, "from": [AID1, AID2], "count": 5},
         "five from either, together")
    cond(G + "?from=%s&category=cleaned+the+room" % AID1,
         {"type": G, "from": [AID1], "fields": {"category": ["cleaned the room"]}, "count": 1}, "+ is a space")
    cond(G + "?from=%s&category=cleaned%%20the%%20room" % AID1,
         {"type": G, "from": [AID1], "fields": {"category": ["cleaned the room"]}, "count": 1}, "%20 is a space too")
    cond(conditions.encode(G, [("from", AID1), ("category", "прибирання")]),
         {"type": G, "from": [AID1], "fields": {"category": ["прибирання"]}, "count": 1}, "non-ASCII is percent-encoded UTF-8")
    cond(G + "?from=%s&category=cleaned the room" % AID1,
         {"type": G, "from": [AID1], "fields": {"category": ["cleaned the room"]}, "count": 1},
         "readers accept a space as it is")
    cond(G + "?from=%s&category=прибирання" % AID1,
         {"type": G, "from": [AID1], "fields": {"category": ["прибирання"]}, "count": 1},
         "readers accept non-ASCII as it is; the same condition as the encoded one")
    cond(G + "?from=%s&category=C++" % AID1,
         {"type": G, "from": [AID1], "fields": {"category": ["C  "]}, "count": 1},
         "+ is a space: C++ must be written C%2B%2B")
    cond(G + "?from=%s&category=a%%26b%%2Bc%%3Dd" % AID1,
         {"type": G, "from": [AID1], "fields": {"category": ["a&b+c=d"]}, "count": 1}, "&, + and = in a value")
    cond("myshop:visit?from=%s&to=%s&since=2026-10-01&count=5" % (AID1, AID2),
         {"type": "myshop:visit", "from": [AID1], "to": [AID2], "since": "2026-10-01", "count": 5})
    cond("?txn=6H24-KE7X", None, "unknown holder key: never met")
    for bad, note in [("", ""), ("?", ""), ("?aid=", ""), ("?aid=short", ""), ("?aid=%s&claim=%s" % (AID1, A), "two holder keys"),
                      ("?claim=abcd", ""), (G, "no query"), (G + "?category=help", "no from"), (G + "?from=x", ""),
                      (G + "?from=%s&count=0" % AID1, ""), (G + "?from=%s&count=many" % AID1, ""),
                      (G + "?from=%s&count=2&count=3" % AID1, "count at most once"),
                      (G + "?from=%s&since=yesterday" % AID1, ""), ("Bad Type?from=" + AID1, ""),
                      ("any(%s,%s)" % (AID1, AID2), "the pre-1.3 form"),
                      (G + "?from=%s&Category=x" % AID1, "keys are lowercase"),
                      (G + "?from=%s&category=%%FF" % AID1, "not UTF-8"),
                      (G + "?from=%s&category=100%%" % AID1, "% that is not an escape must be written %25"),
                      (G + "?from=%s&category=a\nb" % AID1, "control characters")]:
        cond(bad, None, note)
    for c in conds:  # self-check against the reference parser
        p = conditions.parse_one(c["condition"])
        assert (p is not None) == c["parses"], c
        if p is not None:
            assert p.to_json() == c["parsed"], (p.to_json(), c)
    out.json("conditions.json", {"spec": "dzq/1.4", "note": "one condition each; a.req is one of these or a list of them. "
                                 "'parsed' is the decoded condition; compare it, not the text",
                                 "conditions": conds})

    # --- Merkle, digests, claim keys --------------------------------------
    trees = []
    for n in (1, 2, 3, 5, 8, 9):
        leaves = [blake3(("leaf %d" % i).encode()) for i in range(n)]
        trees.append({"leaves": [l.hex() for l in leaves], "root": merkle.root(leaves).hex(),
                      "proofs": [merkle.proof(leaves, i) for i in range(n)]})
    out.json("merkle.json", {"spec": "dzq/1.0", "note": "leaf and siblings are byte arrays (JSON lists of integers), as in period seals",
                             "trees": trees})
    out.json("digests.json", {
        "spec": "dzq/1.0",
        "schemas": {"gratitude 1.0.0": acdc.SCHEMA_GRATITUDE, "gratitude-condition 2.0.0": acdc.SCHEMA_GRATITUDE_CONDITION,
                    "gratitude-private 1.1.0": acdc.SCHEMA_GRATITUDE_PRIVATE,
                    "gratitude-private-condition 2.1.0": acdc.SCHEMA_GRATITUDE_PRIVATE_CONDITION,
                    "dzq:gratitude 1.2.0 (type document)": acdc.SCHEMA_GRATITUDE_12,
                    "look/1 (extension)": acdc.SCHEMA_LOOK,
                    "binding 1.0.0": acdc.SCHEMA_BINDING},
        "blake3_said": [{"input": s, "said": cesr.blake3_said(s)} for s in ["", "dzq", "Дякую"]],
        "redemption_said": [{"gratitude": g1["d"], "said": acdc.redemption_said(g1["d"])}],
        "close_said (extension: promises)": [{"promise": cert["d"], "said": promise_ext.close_said(cert["d"])}],
        "claim_keys": [{"letter_key": letter_key, "scheme": s, "address": a, "public_key": build.claim_key(letter_key, s, a).pub.hex()}
                       for s, a in [("email", "dave@example.org"), ("phone", "+380501234567"), ("github", "octocat")]],
        "claim_message": {"said": g3["d"], "aid": dave.prefix, "message": "dzenq-claim/1|%s|%s" % (g3["d"], dave.prefix)},
    })
    out.json("identities.json", {
        "note": "TEST KEYS ONLY. Seeds are BLAKE3('dzq test vector key|<name>/<n>'). Never use them for anything real.",
        "identities": {c.name: c.prefix for c in (alice, bob, carol, dave, mallory, issuer, old, red, gone, erin,
                                                    dad, marko, sofia, nb, mom, closer)},
    })
    out.json("manifest.json", out.manifest)
    return out.manifest


def main():
    target = os.path.join(ROOT, "vectors")
    if "--check" in sys.argv:
        tmp = tempfile.mkdtemp()
        try:
            generate(tmp)
            diff = []
            for d, _, files in os.walk(tmp):
                for f in files:
                    rel = os.path.relpath(os.path.join(d, f), tmp)
                    a = open(os.path.join(tmp, rel), "rb").read()
                    try:
                        b = open(os.path.join(target, rel), "rb").read()
                    except FileNotFoundError:
                        b = None
                    if a != b:
                        diff.append(rel)
            if diff:
                print("vectors differ from the generator:", *diff, sep="\n  ")
                sys.exit(1)
            print("vectors are up to date")
        finally:
            shutil.rmtree(tmp)
        return
    if os.path.isdir(target):
        for d in ("credentials", "archives", "presentations", "types"):
            shutil.rmtree(os.path.join(target, d), ignore_errors=True)
    m = generate(target)
    print("wrote %d credentials, %d archives, %d presentations" %
          (len(m["credentials"]), len(m["archives"]), len(m["presentations"])))


if __name__ == "__main__":
    main()

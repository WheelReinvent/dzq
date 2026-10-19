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

from dzq import acdc, archive, build, cesr, dq, merkle  # noqa: E402
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
        self.manifest = {"spec": "dzq/1.0", "credentials": [], "archives": [], "presentations": []}

    def write(self, rel, data):
        path = os.path.join(self.base, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        mode = "wb" if isinstance(data, bytes) else "w"
        with open(path, mode, **({} if mode == "wb" else {"encoding": "utf-8", "newline": ""})) as f:
            f.write(data)
        return rel

    def json(self, rel, value):
        return self.write(rel, json.dumps(value, ensure_ascii=False, indent=2) + "\n")

    def credential(self, name, description, bundle, expect, seal=None, kel=None):
        entry = {"name": name, "description": description,
                 "bundle": self.write("credentials/%s.acdc" % name, bundle)}
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

    def presentation(self, name, description, vp, nonce, expect, now=None):
        entry = {"name": name, "description": description,
                 "file": self.write("presentations/%s.json" % name, vp), "nonce": nonce}
        if now is not None:
            entry["now"] = now
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

    group = "any(%s,%s)" % (bob.prefix, carol.prefix)
    g2 = alice.gratitude(attrs(condition=group, title="Дякую команді", message="За вечір", category="team"))
    b2 = alice.bundle(g2)
    out.credential("condition-group", "A thank-you to a condition (schema 2.0.0): any of two AIDs.",
                   b2, valid(said=g2["d"], recipient=group, schema=acdc.SCHEMA_GRATITUDE_CONDITION))

    letter_key = blake3(b"dzq vector letter key")[:16].hex()
    ck = build.claim_key(letter_key, "email", "dave@example.org")
    letter = "claim:" + ck.pub.hex()
    g3 = alice.gratitude(attrs(condition=letter, title="Дякую", message="За лист", category="letter"))
    b3 = alice.bundle(g3)
    out.credential("condition-claim", "A letter to an e-mail address: the condition is one claim key.",
                   b3, valid(said=g3["d"], recipient=letter))

    g4 = alice.gratitude(attrs(condition="any(txn:6H24-KE7X,%s)" % bob.prefix, category="pay"))
    b4 = alice.bundle(g4)
    out.credential("condition-unknown-kind", "A condition with a leaf of a kind this version does not know; the credential is still valid.",
                   b4, valid(recipient="any(txn:6H24-KE7X,%s)" % bob.prefix))

    g5 = alice.gratitude(attrs(condition="any(%s," % bob.prefix, category="oops"))
    out.credential("condition-malformed", "A condition that does not parse: the credential verifies, but nobody can ever hold it (see presentations).",
                   alice.bundle(g5), valid(recipient="any(%s," % bob.prefix))

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
    out.credential("schema-unknown", "A schema SAID this version does not know.",
                   alice.bundle(unknown), invalid("schema"))
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
    out.presentation("group-member", "Carol holds the group thank-you (any of Bob, Carol).",
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
    k_a = build.claim_key(letter_key, "email", "erin@example.org")
    k_b = build.claim_key(letter_key, "phone", "+380501234567")
    erin = build.Controller("erin").incept()
    both = "all(claim:%s,claim:%s)" % (k_a.pub.hex(), k_b.pub.hex())
    g8 = alice.gratitude(attrs(condition=both, message="Обидві адреси"))
    b8 = alice.bundle(g8)
    out.presentation("all-of-two-claims", "all(…) of two claim keys, both claimed.",
                     vp(erin, [b8], claims=[build.claim_proof(k_a, g8["d"], erin.prefix),
                                           build.claim_proof(k_b, g8["d"], erin.prefix)]),
                     NONCE, {"valid": True, "holder": erin.prefix})
    out.presentation("all-of-two-claims-one-missing", "all(…) with only one of the two claims.",
                     vp(erin, [b8], claims=[build.claim_proof(k_a, g8["d"], erin.prefix)]),
                     NONCE, {"valid": False, "code": "credential"})
    out.presentation("unknown-kind-other-leaf", "Bob meets any(txn:…, Bob) through his AID; the unknown leaf is never met.",
                     vp(bob, [b4]), NONCE, {"valid": True, "holder": bob.prefix})
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

    # --- dzq/1.2: look, promises ---------------------------------------
    def stmt(issuer, schema, name, **fields):
        return acdc.new_statement(issuer.prefix, cesr.blake3_said("registry|" + issuer.prefix), schema,
                                  dict({"dt": DT}, **fields), salt=salt(name))

    from dzq import look as look_
    png = bytes.fromhex("89504e470d0a1a0a0000000d4948445200000001000000010802000000907753de"
                        "0000000c4944415478da63f8f3d36a000003bb0207a0e2a0590000000049454e44ae426082")
    png_said = cesr.blake3_said(png)
    look_said, look_text = look_.make_document({"name": "Gold", "layout": "card",
                                                "background": {"color": "#F4E3B5", "image": png_said},
                                                "text": {"color": "#3A2A00", "font": "serif"}, "accent": "#B8860B"})
    g12 = stmt(alice, acdc.SCHEMA_GRATITUDE_12, "g12", i=bob.prefix, category="help", title="Дякую",
               message="З бланком", look="dzenq:" + look_said)
    out.credential("look-full", "dzq/1.2 gratitude naming a look (dzenq:<SAID>), full form.",
                   alice.bundle(g12), valid(said=g12["d"], schema=acdc.SCHEMA_GRATITUDE_12, content="shown"))
    out.credential("look-compact", "The same, compact: the look is hidden with the text.",
                   alice.bundle(acdc.compact(g12)), valid(said=g12["d"], content="hidden"))
    out.credential("look-changed", "The look was swapped for another after signing.",
                   tamper(alice.bundle(g12), "dzenq:" + look_said, "dzenq:" + cesr.blake3_said("other look")), invalid("said"))
    bad_look = json.loads(json.dumps(g12))
    bad_look["a"]["c"]["look"] = "gold"
    out.credential("look-without-source", "A look with no source (SAIDs recomputed): refused.",
                   alice.bundle(resaid(bad_look)), invalid("schema"))
    named = stmt(alice, acdc.SCHEMA_GRATITUDE_12, "g12n", i=bob.prefix, category="help", title="Дякую",
                 message="Каталожний бланк", look="dzenq:gold")
    out.archive("look-carried", "A gratitude with its look/1 document and picture inside the .dzq.",
                archive.make_dzq(alice.bundle(g12), look=(look_said, look_text, {png_said: png})),
                valid(look="ok", content="shown"))
    out.archive("look-named-only", "A catalogue look, named but not carried.",
                archive.make_dzq(alice.bundle(named)), valid(look="named"))
    out.archive("look-document-tampered", "The carried look document was edited: the statement is valid, the look is not used.",
                archive.make_dzq(alice.bundle(g12), look=(look_said, look_text.replace("#B8860B", "#000000"), {png_said: png})),
                {"valid": True, "look": "invalid: the look's SAID does not match its content"})
    gif = b"GIF89a" + b"\x00" * 20
    gif_said = cesr.blake3_said(gif)
    gif_look_said, gif_look_text = look_.make_document({"name": "Gif", "background": {"image": gif_said}})
    g12g = stmt(alice, acdc.SCHEMA_GRATITUDE_12, "g12g", i=bob.prefix, category="help", title="Дякую",
                message="GIF", look="local:" + gif_look_said)
    out.archive("look-forbidden-file", "A carried look uses a GIF: not an allowed file type.",
                archive.make_dzq(alice.bundle(g12g), look=(gif_look_said, gif_look_text, {gif_said: gif})),
                {"valid": True, "look": "invalid: images must be PNG, JPEG or WebP"})

    dad = build.Controller("dad").incept()
    marko = build.Controller("marko").incept()
    sofia = build.Controller("sofia").incept()
    nb = build.Controller("neighbour").incept()
    room = "cleaned%20the%20room"

    def thanks(frm, to, name, category="cleaned the room", dt=DT):
        g = acdc.new_statement(frm.prefix, cesr.blake3_said("registry|" + frm.prefix), acdc.SCHEMA_GRATITUDE_12,
                               {"i": to.prefix, "dt": dt, "category": category, "title": "Дякую", "message": name},
                               salt=salt(name))
        return frm.bundle(acdc.compact(g))

    cert_cond = "all(any(%s,%s),thanks:3/%s/%s)" % (marko.prefix, sofia.prefix, room, dad.prefix)
    cert = stmt(dad, acdc.SCHEMA_PROMISE_CONDITION, "cert", dq=cert_cond, until="2027-06-01T00:00:00+00:00",
                what="Поїздка в гори", note="Приберіть кімнату тричі")
    cert_b = dad.bundle(acdc.compact(cert))
    out.credential("promise", "dzq/1.2 promise to a condition: Marko or Sofia, after 3 thank-yous 'cleaned the room' from Dad.",
                   dad.bundle(cert), valid(said=cert["d"], schema=acdc.SCHEMA_PROMISE_CONDITION, content="shown"))
    to_one = stmt(dad, acdc.SCHEMA_PROMISE, "cert1", i=marko.prefix, what="Кава")
    out.credential("promise-to-one", "A promise to one AID, no condition, no until.",
                   dad.bundle(to_one), valid(schema=acdc.SCHEMA_PROMISE))
    no_what = json.loads(json.dumps(to_one))
    del no_what["a"]["c"]["what"]
    out.credential("promise-without-what", "A promise without 'what' (SAIDs recomputed).",
                   dad.bundle(resaid(no_what)), invalid("schema"))

    t1, t2, t3 = (thanks(dad, marko, "room %d" % i) for i in (1, 2, 3))
    NOW = "2026-11-01T00:00:00+00:00"

    def cert_vp(holder, bundles):
        return build.presentation(holder, bundles, NONCE, DT)

    out.presentation("promise-earned", "Marko shows the promise with three thank-yous from Dad (all compact).",
                     cert_vp(marko, [cert_b, t1, t2, t3]), NONCE, {"valid": True, "promise": "usable"}, now=NOW)
    out.presentation("promise-too-few", "Only two of the three thank-yous.",
                     cert_vp(marko, [cert_b, t1, t2]), NONCE, {"valid": False, "promise": "not-earned"}, now=NOW)
    out.presentation("promise-same-thanks-twice", "The same thank-you three times counts once.",
                     cert_vp(marko, [cert_b, t1, t1, t1]), NONCE, {"valid": False, "promise": "not-earned"}, now=NOW)
    wrong_cat = [thanks(dad, marko, "help %d" % i, category="help") for i in (1, 2)]
    out.presentation("promise-wrong-category", "Three thank-yous, but two are in another category.",
                     cert_vp(marko, [cert_b, t1] + wrong_cat), NONCE, {"valid": False, "promise": "not-earned"}, now=NOW)
    nb_thanks = [thanks(nb, marko, "nb %d" % i) for i in (1, 2)]
    out.presentation("promise-wrong-issuer", "Two of the thank-yous come from a neighbour, not from Dad.",
                     cert_vp(marko, [cert_b, t1] + nb_thanks), NONCE, {"valid": False, "promise": "not-earned"}, now=NOW)
    out.presentation("promise-not-a-holder", "Sofia's friend Erin is not in any(Marko, Sofia), even with three thank-yous.",
                     cert_vp(erin, [cert_b] + [thanks(dad, erin, "e%d" % i) for i in (1, 2, 3)]), NONCE,
                     {"valid": False, "promise": "not-earned"}, now=NOW)
    out.presentation("promise-expired", "Earned, but shown after 'until'.",
                     cert_vp(marko, [cert_b, t1, t2, t3]), NONCE, {"valid": False, "promise": "expired"},
                     now="2027-07-01T00:00:00+00:00")
    two = "thanks:3/%s/%s+%s" % (room, dad.prefix, nb.prefix)
    sum_cert = stmt(dad, acdc.SCHEMA_PROMISE_CONDITION, "sum", dq=two, what="Пиріг")
    out.presentation("promise-two-issuers-add-up", "thanks:3 from Dad+Neighbour: one from Dad and two from the neighbour.",
                     cert_vp(marko, [dad.bundle(acdc.compact(sum_cert)), t1] + nb_thanks), NONCE,
                     {"valid": True, "promise": "usable"}, now=NOW)
    since_cert = stmt(dad, acdc.SCHEMA_PROMISE_CONDITION, "since",
                      dq="thanks:1/%s/%s@2026-10-20T00:00:00Z" % (room, dad.prefix), what="Морозиво")
    out.presentation("promise-before-since", "The only thank-you is dated before the condition's 'since'.",
                     cert_vp(marko, [dad.bundle(acdc.compact(since_cert)), t1]), NONCE,
                     {"valid": False, "promise": "not-earned"}, now=NOW)
    self_cond = "thanks:2/no%%20smoking/%s" % marko.prefix
    self_thanks = [thanks(marko, marko, "day %d" % i, category="no smoking") for i in (1, 2)]
    dads_cert = stmt(dad, acdc.SCHEMA_PROMISE_CONDITION, "dads", dq=self_cond, what="Велосипед")
    out.presentation("promise-self-thanks-elsewhere", "Marko's thank-yous to himself do not count toward Dad's promise.",
                     cert_vp(marko, [dad.bundle(acdc.compact(dads_cert))] + self_thanks), NONCE,
                     {"valid": False, "promise": "not-earned"}, now=NOW)
    own = stmt(marko, acdc.SCHEMA_PROMISE_CONDITION, "own", dq="all(%s,%s)" % (marko.prefix, self_cond), what="Новий светр")
    out.presentation("promise-self-promise", "Marko's promise to himself, earned with his own thank-yous.",
                     cert_vp(marko, [marko.bundle(acdc.compact(own))] + self_thanks), NONCE,
                     {"valid": True, "promise": "usable"}, now=NOW)
    only_certs = stmt(dad, acdc.SCHEMA_PROMISE_CONDITION, "oc", dq="thanks:1/%s/%s" % (room, dad.prefix), what="Чай")
    out.presentation("promise-is-not-a-thank-you", "A promise never counts as a thank-you: two promises, no gratitude.",
                     cert_vp(marko, [dad.bundle(acdc.compact(only_certs)), dad.bundle(acdc.compact(to_one))]), NONCE,
                     {"valid": False, "promise": "not-earned"}, now=NOW)
    closer = build.Controller("closer").incept()
    closing = stmt(closer, acdc.SCHEMA_PROMISE, "closing", i=marko.prefix, what="Кіно")
    closer.interact([{"d": acdc.close_said(closing["d"])}])
    out.credential("promise-closed", "The issuer closed the promise early (a close digest in its KEL): still valid, reports closed_at_sn.",
                   closer.bundle(closing), valid(closed_at_sn=1))
    out.presentation("promise-closed", "Marko shows a promise the issuer has closed.",
                     cert_vp(marko, [closer.bundle(acdc.compact(closing))]), NONCE,
                     {"valid": False, "promise": "closed"}, now=NOW)

    # --- conditions (a.dq) ------------------------------------------------
    A, B = "a" * 64, "b" * 64
    conds = []

    def cond(text, canonical, proved=(), holds=None, note=""):
        c = {"dq": text, "parses": canonical is not None}
        if canonical is not None:
            c["canonical"] = canonical
            c["proved"] = list(proved)
            c["holds"] = holds
        if note:
            c["note"] = note
        conds.append(c)

    aid = "EBP8abc_-Q"
    cond(aid, aid, [aid], True, "a plain AID")
    cond("claim:" + A.upper(), "claim:" + A, ["claim:" + A], True, "claim keys are hex, compared in lower case")
    cond("commitment:ff00", "commitment:ff00", [], False, "older binding flow; not met by dzq/1.0 verifiers")
    cond("alias:abcd01", "alias:abcd01", ["alias:abcd01"], False, "an unknown kind is kept and never met")
    cond("all(any(claim:%s,claim:%s),EAID1)" % (A, B), "all(any(claim:%s,claim:%s),EAID1)" % (A, B),
         ["claim:" + B, "EAID1"], True)
    cond("all(any(claim:%s,claim:%s),EAID1)" % (A, B), "all(any(claim:%s,claim:%s),EAID1)" % (A, B),
         ["claim:" + A], False, "all() needs every branch")
    cond("any(claim:%s,txn:6H24-KE7X,key:EAbc/blue)" % A, "any(claim:%s,txn:6H24-KE7X,key:EAbc/blue)" % A,
         ["claim:" + A], True)
    cond("all(claim:%s,txn:x)" % A, "all(claim:%s,txn:x)" % A, ["claim:" + A, "txn:x"], False,
         "an unknown leaf inside all() makes it unmeetable")
    cond(" any( %s , EAID2 ) " % aid, "any(%s,EAID2)" % aid, ["EAID2"], True, "whitespace around items is allowed")
    cond("thanks:3/help/EAID1", "thanks:3/help/EAID1", [], False, "thanks: is proved by gratitudes in a presentation, never by naming the leaf")
    cond("any(EAID2,thanks:3/help/EAID1)", "any(EAID2,thanks:3/help/EAID1)", ["EAID2"], True)
    cond("\x1c" + aid, None, note="U+001C is not white space")
    cond("any(x\n:y,EAID1)", None, note="a line break inside a leaf")
    for bad in ["", "any(", "any()", "all(a,", "any(a))", "claim:zz", "claim:abcd", "a b", "any(a)(b)", "Bad:x", "k:",
                "any(" * 20 + "a" + ")" * 20]:
        cond(bad, None)
    for c in conds:  # self-check against the reference parser
        p = dq.parse(c["dq"])
        assert (p is not None) == c["parses"], c
        if p is not None:
            assert str(p) == c["canonical"], (str(p), c)
            assert dq.holds(p, lambda leaf, pr=set(c["proved"]): str(leaf) in pr) == c["holds"], c
    out.json("conditions.json", {"spec": "dzq/1.0", "conditions": conds})

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
                    "gratitude 1.2.0": acdc.SCHEMA_GRATITUDE_12, "gratitude-condition 2.2.0": acdc.SCHEMA_GRATITUDE_12_CONDITION,
                    "promise 1.0.0": acdc.SCHEMA_PROMISE, "promise-condition 2.0.0": acdc.SCHEMA_PROMISE_CONDITION,
                    "look/1": acdc.SCHEMA_LOOK,
                    "binding 1.0.0": acdc.SCHEMA_BINDING},
        "blake3_said": [{"input": s, "said": cesr.blake3_said(s)} for s in ["", "dzq", "Дякую"]],
        "redemption_said": [{"gratitude": g1["d"], "said": acdc.redemption_said(g1["d"])}],
        "close_said": [{"promise": cert["d"], "said": acdc.close_said(cert["d"])}],
        "claim_keys": [{"letter_key": letter_key, "scheme": s, "address": a, "public_key": build.claim_key(letter_key, s, a).pub.hex()}
                       for s, a in [("email", "dave@example.org"), ("phone", "+380501234567"), ("github", "octocat")]],
        "claim_message": {"said": g3["d"], "aid": dave.prefix, "message": "dzenq-claim/1|%s|%s" % (g3["d"], dave.prefix)},
    })
    out.json("identities.json", {
        "note": "TEST KEYS ONLY. Seeds are BLAKE3('dzq test vector key|<name>/<n>'). Never use them for anything real.",
        "identities": {c.name: c.prefix for c in (alice, bob, carol, dave, mallory, issuer, old, red, gone, erin,
                                                    dad, marko, sofia, nb, closer)},
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
        for d in ("credentials", "archives", "presentations"):
            shutil.rmtree(os.path.join(target, d), ignore_errors=True)
    m = generate(target)
    print("wrote %d credentials, %d archives, %d presentations" %
          (len(m["credentials"]), len(m["archives"]), len(m["presentations"])))


if __name__ == "__main__":
    main()

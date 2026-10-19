"""Verification of gratitudes, claims and presentations (dzq/1.0 §6, extensions)."""

import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import acdc, cesr, dq, kel, merkle
from .blake3 import blake3


class Result(dict):
    """Outcome of a check. `valid` plus the fields of dzq/1.0 §6.4."""

    def __init__(self, **kw):
        super().__init__(valid=False, code=None, reason=None, said=None, issuer=None,
                         recipient=None, schema=None, sealed=False, anchored_at_sn=None,
                         redeemed_at_sn=None, issuer_kel_sn=None)
        self.update(kw)

    def fail(self, code, reason):
        self.update(valid=False, code=code, reason=reason)
        return self

    def __getattr__(self, k):
        try:
            return self[k]
        except KeyError as e:
            raise AttributeError(k) from e


# --- bundle ----------------------------------------------------------------

def split_bundle(text):
    """`<ACDC JSON><-A## signatures><KEL>` → (acdc raw, [IndexedSig], kel text)."""
    text = text.lstrip()
    try:
        _, end = json.JSONDecoder().raw_decode(text)
    except json.JSONDecodeError as e:
        raise acdc.AcdcError("format", "invalid ACDC JSON: %s" % e) from e
    raw, rest = text[:end], text[end:]
    sigs = []
    if rest.startswith("-"):
        code, group, pos = cesr.one_group(rest, 0)
        if code == "-A":
            sigs = group
        rest = rest[pos:]
    return raw, sigs, rest


def _signed_by(raw, sigs, keys):
    """True when a signature, by the key its index names, verifies over `raw`."""
    data = raw.encode("utf-8")
    for s in sigs:
        if 0 <= s.index < len(keys) and kel.ed25519_verify(keys[s.index], data, s.raw):
            return True
    return False


def _period(view, issuer, said, seal):
    """Where `seal` pins `said` in the issuer's KEL → (close sn, key sets)."""
    if not isinstance(seal, dict) or not isinstance(seal.get("close"), str):
        raise ValueError("unreadable period seal")
    try:
        record = json.loads(seal["close"])
        v, i, prev, since, root, count = (record["v"], record["i"], record["prev"], record["since"],
                                          record["root"], record["count"])
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        raise ValueError("unreadable period close record") from e
    def _uint(x):
        return isinstance(x, int) and not isinstance(x, bool) and x >= 0
    if not all(isinstance(x, str) for x in (v, i, prev, root)) or not _uint(since) or not _uint(count):
        raise ValueError("unreadable period close record")
    if v != "dzq-close/1" or i != issuer:
        raise ValueError("the period close record is not the issuer's")
    close_sn = view.digest_anchor_of(cesr.blake3_said(seal["close"]))
    if close_sn is None:
        raise ValueError("the period is not sealed in the issuer's KEL")
    prf = seal.get("proof")
    if not isinstance(since, int) or since > close_sn or not isinstance(prf, dict) or prf.get("size") != count:
        raise ValueError("inconsistent period close record")
    try:
        root_hash = bytes.fromhex(root)
    except (ValueError, TypeError) as e:
        raise ValueError("bad period root") from e
    if len(root_hash) != 32 or not merkle.verify(root_hash, blake3(said.encode("utf-8")), prf):
        raise ValueError("the thank-you is not in the sealed period")
    return close_sn, view.key_sets_between(since, close_sn)


def check_credential(bundle, seal=None, kel_text=None):
    """Verifies a credential bundle.

    `seal` — the gratitude's period seal, if the holder has one.
    `kel_text` — a fresher copy of the issuer's KEL (from any KERI source);
    when given it is used instead of the KEL inside the bundle.
    """
    r = Result()
    try:
        raw, sigs, bundled_kel = split_bundle(bundle)
        integ = acdc.check_integrity(raw)
    except acdc.AcdcError as e:
        return r.fail(e.code, str(e))
    except cesr.CesrError as e:
        return r.fail("format", "bad signature group: %s" % e)
    r.update(said=integ.said, issuer=integ.issuer, recipient=integ.recipient, schema=integ.schema,
             type=acdc.type_of(integ.schema), dt=integ.acdc["a"].get("dt"))
    if "category" in integ.acdc["a"]:
        r["category"] = integ.acdc["a"]["category"]
    if "until" in integ.acdc["a"]:
        r["until"] = integ.acdc["a"]["until"]
    if integ.schema in acdc.PRIVATE:
        r["content"] = "shown" if integ.content is not None else "hidden"

    try:
        # A fresher copy first, then the bundle's own: for each sequence number
        # the first accepted event wins (KERI "first seen").
        view = kel.build_view((kel_text or "") + bundled_kel, integ.issuer)
    except (kel.KelError, cesr.CesrError, ValueError, TypeError) as e:
        return r.fail("kel", "issuer KEL unreadable: %s" % e)
    if view is None:
        return r.fail("kel", "issuer KEL unknown or invalid")
    r["issuer_kel_sn"] = view.sn
    if not sigs:
        return r.fail("no-signature", "credential carries no signature")

    anchor = view.event_anchor_of(integ.said)
    if anchor is not None:
        # Anchored on its own (gratitudes issued before periods).
        r["anchored_at_sn"] = anchor
        keys = view.keys_at(anchor)
        if not keys or not _signed_by(integ.signed_raw, sigs, keys):
            return r.fail("signature", "signature does not match the issuer's keys at the anchor")
        r["sealed"] = True
    elif seal is not None:
        try:
            close_sn, key_sets = _period(view, integ.issuer, integ.said, seal)
        except ValueError as e:
            return r.fail("seal", str(e))
        if not any(_signed_by(integ.signed_raw, sigs, k) for k in key_sets):
            return r.fail("signature", "signature does not match the issuer's keys in that period")
        r.update(anchored_at_sn=close_sn, sealed=True)
    else:
        keys = view.current_keys()
        if not keys or not _signed_by(integ.signed_raw, sigs, keys):
            return r.fail("not-current", "not sealed, and not signed by the issuer's current keys")

    if r["type"] == "certificate":
        # No redemption for certificates; the issuer may close one early.
        r["closed_at_sn"] = view.digest_anchor_of(acdc.close_said(integ.said))
    else:
        r["redeemed_at_sn"] = view.digest_anchor_of(acdc.redemption_said(integ.said))
        if r["redeemed_at_sn"] is None:
            r["redeemed_at_sn"] = view.digest_anchor_of(integ.said)  # legacy redemption record
    r["valid"] = True
    return r


def _instant(text):
    import datetime
    try:
        t = datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except (ValueError, AttributeError, TypeError):
        return None
    return t if t.tzinfo else t.replace(tzinfo=datetime.timezone.utc)


def thanks_met(leaf, holder, statement_issuer, pool):
    """Does `holder` have enough gratitudes in `pool` (results of valid
    gratitudes the holder holds) for a thanks: leaf of a statement issued by
    `statement_issuer`? (extensions/certificates.md)"""
    t = leaf.thanks
    if t is None:
        return False
    since = _instant(t.since) if t.since else None
    if t.since and since is None:
        return False
    counted = set()
    for g in pool:
        if g.get("type") != "gratitude" or g.get("category") != t.category or g.get("issuer") not in t.issuers:
            continue
        if since is not None:
            when = _instant(g.get("dt"))
            if when is None or when < since:
                continue
        if g.get("issuer") == holder and statement_issuer != holder:
            continue  # a thank-you to yourself counts only toward your own promises to yourself
        counted.add(g["said"])
    return len(counted) >= t.count


# --- claims (extension: letters) -------------------------------------------

def claim_message(said, aid):
    return "dzenq-claim/1|%s|%s" % (said, aid)


def claim_holds(proof):
    """A claim proof {said, aid, key, signature} (hex) verifies."""
    try:
        key = bytes.fromhex(proof["key"])
        sig = bytes.fromhex(proof["signature"])
        if len(key) != 32 or len(sig) != 64:
            return False
        Ed25519PublicKey.from_public_bytes(key).verify(sig, claim_message(proof["said"], proof["aid"]).encode("utf-8"))
        return True
    except (KeyError, TypeError, ValueError, InvalidSignature):
        return False


def holder_meets(recipient, said, holder, claims, schema=None, issuer=None, pool=None):
    """Is `holder` the recipient: the AID in a.i, or a condition in a.dq the
    holder meets with its claims (and, for thanks: leaves, the gratitudes in
    `pool`)?"""
    if schema in acdc.TO_AID:
        return recipient == holder
    cond = dq.parse(recipient)
    if cond is None:
        return False

    def leaf_ok(leaf):
        if leaf.kind == "aid":
            return leaf.value == holder
        if leaf.kind == "claim":
            return any(isinstance(p, dict) and p.get("said") == said and p.get("aid") == holder
                       and p.get("key") == leaf.value and claim_holds(p) for p in claims)
        if leaf.kind == "thanks":
            return pool is not None and thanks_met(leaf, holder, issuer, [g for g in pool if g["said"] != said])
        return False  # commitment: not part of dzq/1.x verification

    return dq.holds(cond, leaf_ok)


# --- presentations (extension: presentation) -------------------------------

def verify_presentation(vp_text, expected_nonce, now=None, kels=()):
    """Holder-bound presentation `dzenq-vp/1`. An empty expected_nonce means
    "display only": it proves nothing about freshness."""
    out = {"valid": False, "holder": None, "code": None, "reason": None, "nonce": None, "credentials": []}

    def fail(code, reason):
        out.update(code=code, reason=reason)
        return out

    try:
        signed = json.loads(vp_text)
        payload_text, signature = signed["payload"], signed["signature"]
        payload = json.loads(payload_text)
        holder = payload["holder"]
        t, nonce, dt = payload["t"], payload["nonce"], payload["dt"]
        credentials, holder_kel = payload["credentials"], payload["holder_kel"]
        claims, seals = payload.get("claims", []), payload.get("seals", {})
        ok = (all(isinstance(x, str) for x in (payload_text, signature, holder, t, nonce, dt, holder_kel))
              and isinstance(credentials, list) and all(isinstance(c, str) for c in credentials)
              and isinstance(claims, list) and isinstance(seals, dict))
    except (json.JSONDecodeError, KeyError, TypeError):
        ok = False
    if not ok:
        return fail("format", "not a DzenQ presentation")
    out["holder"] = holder
    out["nonce"] = nonce
    if t != "dzenq-vp/1":
        return fail("format", "unsupported presentation version")
    if expected_nonce and nonce != expected_nonce:
        return fail("nonce", "nonce mismatch: made for another request")
    try:
        view = kel.build_view(holder_kel, holder)
    except (kel.KelError, cesr.CesrError, ValueError, TypeError):
        view = None
    if view is None or view.rejected:
        return fail("kel", "holder KEL is invalid")
    keys = view.current_keys()
    try:
        sig = cesr.signature_raw(signature)
    except cesr.CesrError:
        sig = None
    if not keys or sig is None or not any(kel.ed25519_verify(k, payload_text.encode("utf-8"), sig) for k in keys):
        return fail("signature", "holder signature is invalid")

    import datetime
    now = now or datetime.datetime.now(datetime.timezone.utc)
    fresher = "".join(kels)
    results = []
    for bundle in credentials:
        r = check_credential(bundle, kel_text=fresher or None)
        if r.said and not r.sealed and isinstance(seals, dict) and r.said in seals:
            r = check_credential(bundle, seal=seals[r.said], kel_text=fresher or None)
        results.append(r)
    # Gratitudes the holder holds without counting other gratitudes: the pool
    # that thanks: leaves count from.
    pool = [r for r in results if r.valid and r.get("type") == "gratitude"
            and holder_meets(r.recipient, r.said, holder, claims, r.schema, r.issuer)]
    all_ok = bool(results)
    for r in results:
        mine = r.valid and holder_meets(r.recipient, r.said, holder, claims, r.schema, r.issuer, pool)
        r["holder_is_recipient"] = mine
        if r.valid and r.get("type") == "certificate":
            until = _instant(r.get("until")) if r.get("until") else None
            if r.get("until") and (until is None or until <= now):
                r["usable"], r["why"] = False, "expired"
            elif r.get("closed_at_sn") is not None:
                r["usable"], r["why"] = False, "closed"
            elif not mine:
                r["usable"], r["why"] = False, "not-earned"
            else:
                r["usable"] = True
            if not r["usable"]:
                all_ok = False
        elif not mine:
            all_ok = False
        out["credentials"].append(r)
    if not all_ok:
        return fail("credential", "a credential is invalid, not the holder's, or a certificate is not usable")
    out["valid"] = True
    return out

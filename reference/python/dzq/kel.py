"""A minimal KERI 1.0 key event log (KEL) verifier.

Enough for checking who signed a gratitude: inception (`icp`), rotation
(`rot`) and interaction (`ixn`) events of a non-delegated, unwitnessed
identifier with Ed25519 keys and simple (numeric) thresholds. Anything
else is reported as unsupported, never silently accepted.
"""

import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import cesr

KERI_PREFIX = "KERI10JSON"


class KelError(ValueError):
    pass


def ed25519_verify(key_qb64, data, raw_sig):
    try:
        Ed25519PublicKey.from_public_bytes(cesr.ed25519_key_raw(key_qb64)).verify(raw_sig, data)
        return True
    except (InvalidSignature, ValueError):
        return False


def parse_stream(text):
    """Splits a CESR text stream into (raw event JSON, event dict, signatures)."""
    out = []
    pos = 0
    decoder = json.JSONDecoder()
    while True:
        while pos < len(text) and text[pos] in " \t\r\n":
            pos += 1
        if pos >= len(text):
            break
        if text[pos] != "{":
            raise KelError("unexpected data in KEL stream at %d" % pos)
        try:
            event, end = decoder.raw_decode(text, pos)
        except json.JSONDecodeError as e:
            raise KelError("bad event JSON: %s" % e) from e
        raw = text[pos:end]
        sigs, pos = cesr.parse_attachments(text, end)
        out.append((raw, event, sigs))
    return out


def _version_size(v, prefix):
    if not isinstance(v, str) or not v.startswith(prefix) or len(v) != 17 or not v.endswith("_"):
        return None
    try:
        return int(v[10:16], 16)
    except ValueError:
        return None


def _threshold(kt):
    if not isinstance(kt, str):
        raise KelError("weighted thresholds are not supported")
    try:
        n = int(kt, 16)
    except ValueError as e:
        raise KelError("bad threshold %r" % kt) from e
    return n


def _event_said_ok(raw, event):
    d = event.get("d")
    if not isinstance(d, str) or len(d) != 44:
        return False
    masked = raw.replace('"d":"%s"' % d, '"d":"%s"' % cesr.SAID_PLACEHOLDER, 1)
    if event.get("t") == "icp" and event.get("i") == d:
        masked = masked.replace('"i":"%s"' % d, '"i":"%s"' % cesr.SAID_PLACEHOLDER, 1)
    return cesr.blake3_said(masked) == d


class Epoch:
    def __init__(self, sn, keys, kt, n, nt):
        self.sn, self.keys, self.kt, self.n, self.nt = sn, keys, kt, n, nt


class KelView:
    """What a KEL says, reduced to what gratitude verification needs."""

    def __init__(self, prefix):
        self.prefix = prefix
        self.sn = -1
        self.last_digest = None
        self.epochs = []
        self.event_seals = []   # (sn, sealed prefix)
        self.digest_seals = []  # (sn, digest)
        self.abandoned = False
        self.rejected = []      # (sn, reason) for events not accepted

    def keys_at(self, sn):
        current = None
        for e in self.epochs:
            if e.sn <= sn:
                current = e
        return current.keys if current else None

    def current_keys(self):
        if self.abandoned or not self.epochs:
            return None
        return self.epochs[-1].keys

    def key_sets_between(self, since, until):
        """Key lists current at some point from sn `since` to sn `until`."""
        out = []
        k = self.keys_at(since)
        if k:
            out.append(k)
        out.extend(e.keys for e in self.epochs if since < e.sn <= until)
        return out

    def event_anchor_of(self, said):
        return next((sn for sn, p in self.event_seals if p == said), None)

    def digest_anchor_of(self, said):
        return next((sn for sn, d in self.digest_seals if d == said), None)


def _signed_enough(raw, sigs, keys, kt):
    data = raw.encode("utf-8")
    ok = set()
    for s in sigs:
        if 0 <= s.index < len(keys) and ed25519_verify(keys[s.index], data, s.raw):
            ok.add(s.index)
    return ok if len(ok) >= kt else None


def _collect_seals(view, sn, seals):
    if not isinstance(seals, list):
        raise KelError("seals must be a list")
    for seal in seals:
        if not isinstance(seal, dict):
            continue
        if set(seal) == {"d"}:
            view.digest_seals.append((sn, seal["d"]))
        elif set(seal) == {"i", "s", "d"}:
            view.event_seals.append((sn, seal["i"]))


def _accept(view, raw, ev, sigs):
    t = ev.get("t")
    size = _version_size(ev.get("v"), KERI_PREFIX)
    if size is None or size != len(raw.encode("utf-8")):
        raise KelError("version string size does not match")
    if not _event_said_ok(raw, ev):
        raise KelError("event SAID does not match")
    try:
        sn = int(ev.get("s", ""), 16)
    except ValueError as e:
        raise KelError("bad sequence number") from e

    if t == "icp":
        if sn != 0 or view.epochs:
            raise KelError("inception must come first, at sn 0")
        if ev.get("bt", "0") != "0" or ev.get("b"):
            raise KelError("witnessed KELs are not supported")
        keys, kt = ev["k"], _threshold(ev["kt"])
        prefix = ev["i"]
        if prefix.startswith("E"):
            if prefix != ev["d"]:
                raise KelError("self-addressing prefix differs from the inception SAID")
        elif not (prefix.startswith("D") and keys == [prefix]):
            raise KelError("unsupported identifier prefix")
        if not _signed_enough(raw, sigs, keys, kt):
            raise KelError("inception is not signed by its keys")
        view.epochs.append(Epoch(0, keys, kt, ev["n"], _threshold(ev["nt"]) if ev["n"] else 0))
        _collect_seals(view, 0, ev.get("a", []))
    elif t in ("rot", "ixn"):
        if view.abandoned:
            raise KelError("identifier was abandoned")
        if sn != view.sn + 1:
            raise KelError("out-of-order event (sn %d after %d)" % (sn, view.sn))
        if ev.get("p") != view.last_digest:
            raise KelError("prior event digest does not match")
        prior = view.epochs[-1]
        if t == "ixn":
            if not _signed_enough(raw, sigs, prior.keys, prior.kt):
                raise KelError("interaction is not signed by the current keys")
            _collect_seals(view, sn, ev.get("a", []))
        else:
            if ev.get("bt", "0") != "0" or ev.get("br") or ev.get("ba"):
                raise KelError("witnessed KELs are not supported")
            keys, kt = ev["k"], _threshold(ev["kt"])
            signed = _signed_enough(raw, sigs, keys, kt)
            if not signed:
                raise KelError("rotation is not signed by its new keys")
            committed = [i for i in signed if cesr.blake3_said(keys[i]) in prior.n]
            if len(committed) < prior.nt or not prior.n:
                raise KelError("rotation keys were not pre-committed")
            view.epochs.append(Epoch(sn, keys, kt, ev["n"], _threshold(ev["nt"]) if ev["n"] else 0))
            _collect_seals(view, sn, ev.get("a", []))
            if not ev["n"]:
                view.abandoned = True
    elif t in ("dip", "drt"):
        raise KelError("delegated identifiers are not supported by this verifier")
    else:
        raise KelError("unsupported event type %r" % t)
    view.sn = sn
    view.last_digest = ev["d"]


def build_view(kel_text, prefix=None):
    """Processes a KEL stream and returns the KelView of `prefix`.

    Events of other identifiers are ignored. The first event that does not
    verify stops the log (later events cannot chain to it); it and every
    later event of the prefix are listed in `rejected`. Returns None when
    no event of the prefix was accepted.
    """
    events = parse_stream(kel_text)
    if prefix is None:
        prefix = next((ev.get("i") for _, ev, _ in events), None)
    view = KelView(prefix)
    broken = None
    for raw, ev, sigs in events:
        if ev.get("i") != prefix:
            continue
        if broken is not None:
            view.rejected.append((ev.get("s"), "follows a rejected event"))
            continue
        # A copy of an accepted event (first seen wins).
        try:
            sn = int(ev.get("s", ""), 16)
        except ValueError:
            sn = None
        if sn is not None and sn <= view.sn:
            continue
        try:
            _accept(view, raw, ev, sigs)
        except (KelError, KeyError, TypeError, cesr.CesrError) as e:
            broken = str(e)
            view.rejected.append((ev.get("s"), broken))
    return view if view.epochs else None

"""The issuing side, for test vectors and tools: a single-key KERI identifier
that can incept, rotate, interact, sign gratitudes and seal periods.

Not a wallet. Keys come from fixed seeds so the vectors are reproducible.
"""

import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from . import acdc, cesr, merkle
from .blake3 import blake3, derive_key


def _dumps(v):
    return json.dumps(v, ensure_ascii=False, separators=(",", ":"))


class Key:
    def __init__(self, seed):
        self.seed = seed
        self.sk = Ed25519PrivateKey.from_private_bytes(seed)
        self.pub = self.sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.qb64 = cesr.ed25519_key_qb64(self.pub)

    @classmethod
    def named(cls, name):
        return cls(blake3(b"dzq test vector key|" + name.encode("utf-8")))

    def sign(self, data):
        if isinstance(data, str):
            data = data.encode("utf-8")
        return self.sk.sign(data)


def _keri_event(fields, self_addressing_prefix=False):
    ev = dict(fields)
    ev["v"] = "KERI10JSON000000_"
    ev["d"] = cesr.SAID_PLACEHOLDER
    if self_addressing_prefix:
        ev["i"] = cesr.SAID_PLACEHOLDER
    ev["v"] = "KERI10JSON%06x_" % len(_dumps(ev).encode("utf-8"))
    said = cesr.blake3_said(_dumps(ev))
    ev["d"] = said
    if self_addressing_prefix:
        ev["i"] = said
    return ev


class Controller:
    """A single-key identifier with pre-rotation, like a DzenQ root identity."""

    def __init__(self, name):
        self.name = name
        self.generation = 0
        self.current = Key.named("%s/0" % name)
        self.next = Key.named("%s/1" % name)
        self.events = []        # (raw, signed stream text)
        self.sn = -1
        self.last = None
        self.prefix = None
        self.abandoned = False

    def _append(self, ev, key):
        raw = _dumps(ev)
        sig = cesr.indexed_sig_qb64(key.sign(raw), 0)
        self.events.append(raw + cesr.counter_indexed_sigs([sig]))
        self.sn = int(ev["s"], 16)
        self.last = ev["d"]

    def incept(self):
        ev = _keri_event({
            "v": "", "t": "icp", "d": "", "i": "", "s": "0",
            "kt": "1", "k": [self.current.qb64],
            "nt": "1", "n": [cesr.blake3_said(self.next.qb64)],
            "bt": "0", "b": [], "c": [], "a": [],
        }, self_addressing_prefix=True)
        self.prefix = ev["i"]
        self._append(ev, self.current)
        return self

    def rotate(self, abandon=False, seals=()):
        self.generation += 1
        new_current = self.next
        new_next = None if abandon else Key.named("%s/%d" % (self.name, self.generation + 1))
        ev = _keri_event({
            "v": "", "t": "rot", "d": "", "i": self.prefix, "s": "%x" % (self.sn + 1), "p": self.last,
            "kt": "1", "k": [new_current.qb64],
            "nt": "0" if abandon else "1", "n": [] if abandon else [cesr.blake3_said(new_next.qb64)],
            "bt": "0", "br": [], "ba": [], "a": list(seals),
        })
        self._append(ev, new_current)
        self.current, self.next = new_current, new_next
        self.abandoned = abandon
        return self

    def interact(self, seals, key=None):
        ev = _keri_event({
            "v": "", "t": "ixn", "d": "", "i": self.prefix, "s": "%x" % (self.sn + 1), "p": self.last,
            "a": list(seals),
        })
        self._append(ev, key or self.current)
        return ev

    def kel(self):
        return "".join(self.events)

    # --- gratitudes --------------------------------------------------------

    def gratitude(self, attributes, registry=None):
        return acdc.new_gratitude(self.prefix, registry or cesr.blake3_said("registry|" + self.prefix), attributes)

    def bundle(self, credential, key=None, kel=None, index=0):
        raw = acdc.dumps(credential) if isinstance(credential, dict) else credential
        sig = cesr.indexed_sig_qb64((key or self.current).sign(raw), index)
        return raw + cesr.counter_indexed_sigs([sig]) + (self.kel() if kel is None else kel)

    def close_period(self, saids, since, prev=""):
        """Seals `saids` with one interaction event. Returns {said: period seal}."""
        leaves = [blake3(s.encode("utf-8")) for s in saids]
        record = _dumps({"v": "dzq-close/1", "i": self.prefix, "prev": prev, "since": since,
                         "root": merkle.root(leaves).hex(), "count": len(leaves)})
        self.interact([{"d": cesr.blake3_said(record)}])
        return {s: {"close": record, "proof": merkle.proof(leaves, i)} for i, s in enumerate(saids)}

    def redeem(self, said):
        self.interact([{"d": acdc.redemption_said(said)}])

    def anchor(self, said):
        """Old-style per-gratitude anchor: an event seal naming the SAID."""
        self.interact([{"i": said, "s": "0", "d": said}])

    def sign_payload(self, text):
        return cesr.signature_qb64(self.current.sign(text))


# --- letters (extension: letters) ------------------------------------------

def claim_key(letter_key_hex, scheme, normalized):
    material = bytes.fromhex(letter_key_hex.split(".")[0]) + b"|" + scheme.encode() + b":" + normalized.encode("utf-8")
    return Key(derive_key("DzenQ claim key v1", material))


def claim_proof(key, said, aid):
    msg = "dzenq-claim/1|%s|%s" % (said, aid)
    return {"said": said, "aid": aid, "key": key.pub.hex(), "signature": key.sign(msg).hex()}


def presentation(holder, credentials, nonce, dt, claims=(), seals=None):
    payload = {"t": "dzenq-vp/1", "holder": holder.prefix, "nonce": nonce, "dt": dt,
               "credentials": list(credentials), "holder_kel": holder.kel()}
    if claims:
        payload["claims"] = list(claims)
    if seals:
        payload["seals"] = seals
    text = _dumps(payload)
    return _dumps({"payload": text, "signature": holder.sign_payload(text)})

"""The few CESR primitives and count codes a gratitude needs (KERI 1.0 text domain)."""

import base64

from .blake3 import blake3

SAID_PLACEHOLDER = "#" * 44


class CesrError(ValueError):
    pass


def _b64d(s):
    return base64.urlsafe_b64decode(s.encode("ascii"))


def _b64e(b):
    return base64.urlsafe_b64encode(b).decode("ascii")


def encode(code, raw):
    """qb64 of `raw` for a fixed-size code whose length equals its pad size."""
    ps = (3 - len(raw) % 3) % 3
    if len(code) != ps:
        raise CesrError("code %r does not fit raw of %d bytes" % (code, len(raw)))
    return code + _b64e(b"\x00" * ps + raw)[ps:]


def decode(qb64, code_len, total_len):
    if len(qb64) != total_len:
        raise CesrError("bad primitive length: %r" % qb64[:8])
    try:
        return _b64d("A" * code_len + qb64[code_len:])[code_len:]
    except Exception as e:  # binascii.Error
        raise CesrError("bad base64 in primitive") from e


# --- digests ----------------------------------------------------------------

def blake3_said(data):
    """Blake3-256 digest in qb64 (`E…`, 44 chars). `data` is bytes or str."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return encode("E", blake3(data))


def digest_raw(qb64):
    if not qb64.startswith("E"):
        raise CesrError("only Blake3-256 digests (E) are supported")
    return decode(qb64, 1, 44)


# --- keys and signatures ----------------------------------------------------

def ed25519_key_raw(qb64):
    """Raw public key of a `D` (transferable) or `B` (non-transferable) Ed25519 key."""
    if not qb64 or qb64[0] not in "DB":
        raise CesrError("only Ed25519 keys (D/B) are supported")
    return decode(qb64, 1, 44)


def ed25519_key_qb64(raw, transferable=True):
    return encode("D" if transferable else "B", raw)


def signature_raw(qb64):
    """Raw bytes of a non-indexed Ed25519 signature (`0B…`, 88 chars)."""
    if not qb64.startswith("0B"):
        raise CesrError("only Ed25519 signatures (0B) are supported")
    return decode(qb64, 2, 88)


def signature_qb64(raw):
    return encode("0B", raw)


B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def b64_int(s):
    n = 0
    for c in s:
        i = B64.find(c)
        if i < 0:
            raise CesrError("bad base64 digit %r" % c)
        n = n * 64 + i
    return n


def int_b64(n, width):
    out = ""
    for _ in range(width):
        out = B64[n % 64] + out
        n //= 64
    if n:
        raise CesrError("number too large")
    return out


class IndexedSig:
    def __init__(self, index, raw, ondex=None):
        self.index, self.raw, self.ondex = index, raw, ondex

    def __repr__(self):
        return "IndexedSig(%d)" % self.index


def indexed_sig_qb64(raw, index=0):
    """Ed25519 indexed signature, current and prior index the same (code `A`)."""
    if index >= 64:
        raise CesrError("index too large for the small code")
    return "A" + B64[index] + _b64e(b"\x00\x00" + raw)[2:]


def _indexed_sig(text, pos):
    code = text[pos:pos + 1]
    if code in ("A", "B"):  # Ed25519 both-same / current-only, 1-char index
        q = text[pos:pos + 88]
        if len(q) != 88:
            raise CesrError("truncated indexed signature")
        return IndexedSig(b64_int(q[1]), decode(q, 2, 88)), pos + 88
    if text[pos:pos + 2] in ("2A", "2B"):  # big index variants
        q = text[pos:pos + 92]
        if len(q) != 92:
            raise CesrError("truncated indexed signature")
        return IndexedSig(b64_int(q[2:4]), _b64d("AAAA" + q[4:])[4:][-64:], b64_int(q[4:6])), pos + 92
    raise CesrError("unsupported indexed signature code %r" % text[pos:pos + 2])


def counter_indexed_sigs(sigs):
    """`-A##` group of controller signatures."""
    return "-A" + int_b64(len(sigs), 2) + "".join(sigs)


# --- attachment groups ------------------------------------------------------

# Sizes (in qb64 characters) of the fixed primitives inside the groups we skip.
_SEQNER = 24     # 0A + 22
_DATER = 36      # 1AAG + 32
_DIGEST = 44
_PREFIX = 44
_SIG = 88


def parse_attachments(text, pos):
    """Reads the attachment groups after an event, starting at `pos`.

    Returns (controller signatures, next position). Groups other than
    controller signatures are skipped; they do not affect what a verifier
    of gratitudes needs.
    """
    sigs = []
    while pos < len(text) and text[pos] == "-":
        code, group, pos = one_group(text, pos)
        if code == "-A":
            sigs.extend(group)
    return sigs, pos


def one_group(text, pos):
    code = text[pos:pos + 2]
    if len(text) < pos + 4:
        raise CesrError("truncated count code")
    count = b64_int(text[pos + 2:pos + 4])
    pos += 4
    group = []
    if code in ("-A", "-B"):
        for _ in range(count):
            s, pos = _indexed_sig(text, pos)
            group.append(s)
    elif code == "-C":
        pos += count * (_PREFIX + _SIG)
    elif code == "-D":
        pos += count * (_PREFIX + _SEQNER + _DIGEST + _SIG)
    elif code == "-E":
        pos += count * (_SEQNER + _DATER)
    elif code == "-G":
        pos += count * (_SEQNER + _DIGEST)
    elif code in ("-F", "-H"):
        for _ in range(count):
            pos += _PREFIX + (_SEQNER + _DIGEST if code == "-F" else 0)
            if text[pos:pos + 2] != "-A":
                raise CesrError("expected signatures in %s group" % code)
            _, _, pos = one_group(text, pos)
    elif code == "-V":
        pos += count * 4
    else:
        raise CesrError("unsupported attachment group %r" % code)
    if pos > len(text):
        raise CesrError("truncated attachment group %r" % code)
    return code, group, pos

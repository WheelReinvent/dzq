"""Pure-Python BLAKE3 (hash and derive_key modes, 32-byte output).

A direct port of the BLAKE3 reference implementation. Slow, but it has no
dependencies, which is the point of a reference verifier: a .dzq file can be
checked with nothing but Python and an Ed25519 library.
"""

OUT_LEN = 32
BLOCK_LEN = 64
CHUNK_LEN = 1024

CHUNK_START = 1 << 0
CHUNK_END = 1 << 1
PARENT = 1 << 2
ROOT = 1 << 3
KEYED_HASH = 1 << 4
DERIVE_KEY_CONTEXT = 1 << 5
DERIVE_KEY_MATERIAL = 1 << 6

IV = (
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
)
MSG_PERMUTATION = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)
M32 = 0xFFFFFFFF


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & M32


def _g(s, a, b, c, d, mx, my):
    s[a] = (s[a] + s[b] + mx) & M32
    s[d] = _rotr(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & M32
    s[b] = _rotr(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b] + my) & M32
    s[d] = _rotr(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & M32
    s[b] = _rotr(s[b] ^ s[c], 7)


def _round(s, m):
    _g(s, 0, 4, 8, 12, m[0], m[1])
    _g(s, 1, 5, 9, 13, m[2], m[3])
    _g(s, 2, 6, 10, 14, m[4], m[5])
    _g(s, 3, 7, 11, 15, m[6], m[7])
    _g(s, 0, 5, 10, 15, m[8], m[9])
    _g(s, 1, 6, 11, 12, m[10], m[11])
    _g(s, 2, 7, 8, 13, m[12], m[13])
    _g(s, 3, 4, 9, 14, m[14], m[15])


def _compress(cv, block_words, counter, block_len, flags):
    s = [
        cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
        IV[0], IV[1], IV[2], IV[3],
        counter & M32, (counter >> 32) & M32, block_len, flags,
    ]
    m = list(block_words)
    for r in range(7):
        _round(s, m)
        if r < 6:
            m = [m[i] for i in MSG_PERMUTATION]
    for i in range(8):
        s[i] ^= s[i + 8]
        s[i + 8] ^= cv[i]
    return s


def _words(block):
    block = block + b"\x00" * (BLOCK_LEN - len(block))
    return [int.from_bytes(block[i:i + 4], "little") for i in range(0, BLOCK_LEN, 4)]


class _Output:
    def __init__(self, cv, block_words, counter, block_len, flags):
        self.cv, self.block_words, self.counter = cv, block_words, counter
        self.block_len, self.flags = block_len, flags

    def chaining_value(self):
        return _compress(self.cv, self.block_words, self.counter, self.block_len, self.flags)[:8]

    def root_bytes(self, length=OUT_LEN):
        out = b""
        counter = 0
        while len(out) < length:
            words = _compress(self.cv, self.block_words, counter, self.block_len, self.flags | ROOT)
            out += b"".join(w.to_bytes(4, "little") for w in words)
            counter += 1
        return out[:length]


class _ChunkState:
    def __init__(self, key, chunk_counter, flags):
        self.cv = list(key)
        self.chunk_counter = chunk_counter
        self.block = b""
        self.blocks_compressed = 0
        self.flags = flags

    def length(self):
        return BLOCK_LEN * self.blocks_compressed + len(self.block)

    def _start_flag(self):
        return CHUNK_START if self.blocks_compressed == 0 else 0

    def update(self, data):
        while data:
            if len(self.block) == BLOCK_LEN:
                self.cv = _compress(
                    self.cv, _words(self.block), self.chunk_counter, BLOCK_LEN,
                    self.flags | self._start_flag(),
                )[:8]
                self.blocks_compressed += 1
                self.block = b""
            take = min(BLOCK_LEN - len(self.block), len(data))
            self.block += data[:take]
            data = data[take:]

    def output(self):
        return _Output(
            self.cv, _words(self.block), self.chunk_counter, len(self.block),
            self.flags | self._start_flag() | CHUNK_END,
        )


def _parent_output(left, right, key, flags):
    return _Output(list(key), list(left) + list(right), 0, BLOCK_LEN, PARENT | flags)


class Hasher:
    def __init__(self, key_words=IV, flags=0):
        self.key = list(key_words)
        self.flags = flags
        self.chunk = _ChunkState(self.key, 0, flags)
        self.cv_stack = []

    def _add_chunk_cv(self, cv, total_chunks):
        while total_chunks & 1 == 0:
            cv = _parent_output(self.cv_stack.pop(), cv, self.key, self.flags).chaining_value()
            total_chunks >>= 1
        self.cv_stack.append(cv)

    def update(self, data):
        data = bytes(data)
        while data:
            if self.chunk.length() == CHUNK_LEN:
                cv = self.chunk.output().chaining_value()
                total = self.chunk.chunk_counter + 1
                self._add_chunk_cv(cv, total)
                self.chunk = _ChunkState(self.key, total, self.flags)
            take = min(CHUNK_LEN - self.chunk.length(), len(data))
            self.chunk.update(data[:take])
            data = data[take:]
        return self

    def digest(self, length=OUT_LEN):
        out = self.chunk.output()
        for cv in reversed(self.cv_stack):
            out = _parent_output(cv, out.chaining_value(), self.key, self.flags)
        return out.root_bytes(length)

    def hexdigest(self, length=OUT_LEN):
        return self.digest(length).hex()


def blake3(data=b""):
    """BLAKE3 hash of `data` (32 bytes)."""
    return Hasher().update(data).digest()


def derive_key(context, material):
    """BLAKE3 derive_key(context, key_material) (32 bytes)."""
    if isinstance(context, str):
        context = context.encode("utf-8")
    context_key = Hasher(IV, DERIVE_KEY_CONTEXT).update(context).digest()
    words = [int.from_bytes(context_key[i:i + 4], "little") for i in range(0, 32, 4)]
    return Hasher(words, DERIVE_KEY_MATERIAL).update(material).digest()

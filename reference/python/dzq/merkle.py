"""Merkle trees of period seals (extension: periods).

RFC 6962-style domain separation over BLAKE3: leaf node = H(0x00 ‖ leaf),
inner node = H(0x01 ‖ left ‖ right), root = H(0x02 ‖ count as u64 LE ‖ top).
An odd last node is carried up a level unchanged.
"""

from .blake3 import blake3

LEAF, NODE, ROOT = b"\x00", b"\x01", b"\x02"


def leaf_node(leaf):
    return blake3(LEAF + leaf)


def inner_node(left, right):
    return blake3(NODE + left + right)


def sized_root(size, top):
    return blake3(ROOT + size.to_bytes(8, "little") + top)


def _level_up(nodes):
    return [inner_node(nodes[i], nodes[i + 1]) if i + 1 < len(nodes) else nodes[i]
            for i in range(0, len(nodes), 2)]


def root(leaves):
    if not leaves:
        return sized_root(0, blake3(b""))
    level = [leaf_node(l) for l in leaves]
    while len(level) > 1:
        level = _level_up(level)
    return sized_root(len(leaves), level[0])


def proof(leaves, index):
    siblings = []
    level = [leaf_node(l) for l in leaves]
    idx = index
    while len(level) > 1:
        sib = idx ^ 1
        if sib < len(level):
            siblings.append(level[sib])
        level = _level_up(level)
        idx //= 2
    return {"leaf": list(leaves[index]), "index": index, "size": len(leaves),
            "siblings": [list(s) for s in siblings]}


def _bytes32(v):
    if not isinstance(v, list) or len(v) != 32 or not all(isinstance(x, int) and 0 <= x < 256 for x in v):
        raise ValueError("expected 32 bytes as a list of integers")
    return bytes(v)


def verify(root_hash, leaf, prf):
    """Does `prf` (the JSON form) show that `leaf` (32 bytes) is under `root_hash`?"""
    try:
        p_leaf = _bytes32(prf["leaf"])
        index, size = prf["index"], prf["size"]
        siblings = [_bytes32(s) for s in prf["siblings"]]
    except (KeyError, TypeError, ValueError):
        return False
    if not isinstance(index, int) or not isinstance(size, int) or p_leaf != leaf or not 0 <= index < size:
        return False
    node = leaf_node(leaf)
    idx, width = index, size
    it = iter(siblings)
    while width > 1:
        if idx % 2 == 1:
            s = next(it, None)
            if s is None:
                return False
            node = inner_node(s, node)
        elif idx + 1 < width:
            s = next(it, None)
            if s is None:
                return False
            node = inner_node(node, s)
        idx //= 2
        width = (width + 1) // 2
    return next(it, None) is None and sized_root(size, node) == root_hash

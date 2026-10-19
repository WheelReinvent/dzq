# Extension: periods (`dzq-close/1`)

**Status:** part of dzq/1.0, optional. Implemented by DzenQ since 2026-10-12.

A gratitude is signed and valid at once, without a key event (an *open*
gratitude, SPEC §6.2 step 7). That keeps the issuer's KEL small, but an open
gratitude is only valid while the key that signed it is current. A
**period** fixes many gratitudes in the KEL with one event: after that they
are *sealed* and survive any later rotation.

## Close record

The issuer keeps the SAIDs it issued since its last close, in issuing order.
Closing writes one `ixn` event whose seal list holds a digest seal
`{"d": <digest of the close record>}`. The close record is a JSON object:

```json
{"v":"dzq-close/1","i":"<issuer AID>","prev":"<digest of the previous close record, or empty>",
 "since":<sn of the KEL event where the period began>,"root":"<Merkle root, 64 hex>","count":<number of gratitudes>}
```

- The digest of the record is Blake3-256 qb64 over its **exact bytes** as
  carried in the seal (the record has no `d` field; this digest is not a
  SAID). Anyone who has the record bytes can recompute it; nobody needs
  to re-serialize it.
- `since` is the sequence number of the previous close event, or of the
  event the issuer's period started at (0 for the first).
- `count` is public: the KEL shows how many gratitudes an issuer gave per
  period, never to whom.

### When to close

An issuer SHOULD close its open period before every rotation (with the old
key), and MAY close at any other time. DzenQ closes on the first action of
each UTC day, before every rotation, right after moving to a new device
(for the period the old device left open), and on demand.

## Merkle tree

Leaves are `Blake3(SAID)` (the 32 raw bytes of Blake3-256 over the UTF-8
SAID text), in issuing order. Nodes use domain separation in the style of
RFC 6962:

```
leaf node  = Blake3(0x00 ‖ leaf)
inner node = Blake3(0x01 ‖ left ‖ right)
root       = Blake3(0x02 ‖ count as 8-byte little-endian ‖ top node)
```

An odd last node at a level is carried up unchanged. The empty tree's root
is `Blake3(0x02 ‖ 0 ‖ Blake3(""))`. The root commits to the number of
leaves.

## Period seal

What a holder keeps (and presents) for one gratitude:

```json
{"close": "<the close record, as a JSON string>",
 "proof": {"leaf": [32 bytes], "index": i, "size": n, "siblings": [[32 bytes], …]}}
```

`leaf` and each sibling are written as JSON arrays of 32 integers (this is
how DzenQ serializes them; a later version may add a hex form).

## Verification

Given a gratitude with SAID `S`, issuer `I`, its signature, the issuer's KEL
and a period seal, the gratitude is **sealed** when all hold:

1. `close` parses as JSON with `v = "dzq-close/1"` and `i = I`.
2. A digest seal of `Blake3-256-qb64(close bytes)` is in an accepted event
   of `I`'s KEL, at sequence number `c`.
3. `since ≤ c` and `proof.size = count`.
4. `proof.leaf = Blake3(S)` and the Merkle path recomputes `root`:
   walking up from `leaf node(leaf)` with index `i` and width `n`, at each
   level take the next sibling on the left if the index is odd, on the
   right if the index is even and not the last node of the level, and none
   otherwise; halve the index, set width to ⌈width/2⌉; all siblings must be
   used; finally `root(n, node)` must equal `root`.
5. A signature verifies with a key current at some point from `since` to
   `c`: the keys current at `since`, or those of any establishment event
   after `since` up to `c`.

Result: valid, `sealed`, `anchored_at_sn = c`. Any failure of 1–4 is code
`seal`; of 5, `signature`.

Step 5 covers a period sealed right after a move to a new device: the
gratitudes the old key signed before the rotation are still sealed.

## Vectors

`rotated-sealed`, `rotated-sealed-second-leaf`, `rotated-no-seal`,
`rotated-unsealed`, `seal-of-another`, `seal-not-anchored`, and
`vectors/merkle.json`.

## Where holders get seals

Out of scope. DzenQ's watcher serves them (`GET /watcher/sealed/<SAID>`);
an issuer may also send them directly. A seal is self-proving: it can come
from anywhere.

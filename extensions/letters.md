# Extension: letters (claim keys, `dzenq-claim/1`)

**Status:** part of dzq/1.0, optional. Implemented by DzenQ since 2026-10-12.

A thank-you to an e-mail address, a phone number or an account on another
service names no identifier. It is a gratitude to a condition (schema 2.0.0)
whose leaves are one-time **claim keys**: `claim:<64 hex>`, an Ed25519
public key. Whoever is handed the matching private key — through that
address, a link, a QR code — can sign the letter over to their own AID.

Nobody attests the address. It is only the channel the key went through.
The proof is the claim key's own signature: offline, needing neither the
issuer's app nor the mail provider, and valid forever.

## Claim proof

```json
{"said": "<gratitude SAID>", "aid": "<holder AID>", "key": "<claim public key, 64 hex>", "signature": "<128 hex>"}
```

`signature` is Ed25519 by the claim key over the UTF-8 bytes of

```
dzenq-claim/1|<gratitude SAID>|<holder AID>
```

A `claim:<key>` leaf of a gratitude with SAID `S` is **proved for holder
`H`** by a claim proof with `said = S`, `aid = H`, `key` equal to the leaf's
key (lowercase hex) and a signature that verifies. Verifiers SHOULD use
strict Ed25519 verification (reject non-canonical encodings and small-order
keys).

Several identifiers may claim one letter (the same person's second account,
or everyone who got the link). A claim proof cannot be moved to another AID
or another gratitude: both are inside the signed text.

## Deriving claim keys (interoperable letters)

This part matters only for applications that want to *send* letters other
applications can open, or open letters sent by DzenQ.

```
letter key   = 16 random bytes, carried as 32 lowercase hex characters
               (in a link: anything after the first "." is not part of the key)
claim seed   = BLAKE3.derive_key("DzenQ claim key v1",
                                 letter key ‖ "|" ‖ scheme ‖ ":" ‖ normalized address)
claim key    = Ed25519 public key of the 32-byte seed
```

Schemes and normalization:

| Scheme | Normalized address |
|---|---|
| `email` | trimmed, lowercase; must contain `@` |
| `phone` | digits and `+` only; a 10-digit number starting with `0` gets `+38` (DzenQ's home market, as on its server); `+` added if missing; at least 8 characters |
| any other scheme of 1–16 lowercase letters/digits starting with a letter, except `txn` (`github`, `x`, …) | the handle, trimmed, without a leading `@`, lowercase; 1–64 of `[a-z0-9._-]` |

One letter to several addresses is `any(claim:…, claim:…)`. `all(…)` of
claim keys of one letter proves nothing more than `any(…)` (whoever has the
letter key can make all of them) and SHOULD NOT be issued; it is still
valid syntax.

The letter key travels only to the address: in DzenQ, as a waiting letter
the owner of the address fetches after signing in with it, or in a link
`#k=…`, or in a QR code. How it travels is out of scope.

## Vectors

`condition-claim`, `letter-claimed`, `letter-no-claim`,
`letter-claim-for-another`, `letter-claim-bad-signature`,
`all-of-two-claims*`, and `claim_keys` in `vectors/digests.json`.

## Not part of dzq/1.0

The former `alias:<digest>` leaf, which relied on statements signed by
DzenQ's server, was removed in DzenQ on 2026-10-12. Such a leaf is now an
unknown kind: never met.

# Extension: holder-bound presentation (`dzenq-vp/1`)

**Status:** part of dzq/1.0, optional. Used by DzenQ "doors".

A gratitude file can be copied by anyone. To show that *you* are the one it
is for — and that you are showing it now, not replaying an old screenshot —
you sign a presentation over a code the verifier gave you.

## Format

```json
{"payload": "<payload, as a JSON string>", "signature": "<Ed25519 signature by the holder, CESR 0B…>"}
```

The payload (JSON, signed as the exact bytes of the string):

| Field | Content |
|---|---|
| `t` | `"dzenq-vp/1"` |
| `holder` | holder AID |
| `nonce` | the code the verifier issued (at least 8 characters) |
| `dt` | RFC 3339 time of making the presentation (a claim, not checked) |
| `credentials` | list of credential bundles (SPEC §5) |
| `holder_kel` | the holder's KEL, CESR text |
| `claims` | optional: claim proofs (letters extension) for gratitudes to conditions |
| `seals` | optional: map gratitude SAID → period seal (periods extension) |

## Verification

The presentation is valid when all hold:

1. It parses, `t` is `dzenq-vp/1`. — `format`
2. If the verifier issued a code: `nonce` equals it. — `nonce`
   A verifier that issued no code MAY still check the rest, but the result
   only *shows* gratitudes; it proves nothing about who is holding the
   phone. Applications SHOULD label it as a display, not a proof.
3. `holder_kel` is a valid KEL of `holder` and **every** event in it is
   accepted. — `kel`
4. `signature` verifies over the payload bytes with the holder's current
   key. — `signature`
5. There is at least one credential, and for each: it verifies (SPEC §6,
   using its period seal from `seals` if it is not sealed otherwise), and
   the holder is its recipient: `a.i` equals `holder`, or the condition
   `a.dq` holds where an AID leaf is met when it equals `holder` and a
   `claim:` leaf is met by a claim proof in `claims` for this gratitude and
   this holder. — `credential`

An online verifier SHOULD load the holder's KEL from a KERI source first, so
that a device the holder moved away from (and whose key was rotated out)
cannot present.

## Freshness of the issuer's KEL

Each credential bundle carries the issuer's KEL as the holder has it. A
sealed gratitude whose issuer has rotated since is only verifiable if that
KEL includes the period's closing event; holders SHOULD refresh the
bundle's KEL when they receive a period seal (vector
`sealed-after-rotation`), or the verifier must load a fresh KEL itself.

## Vectors

`vectors/presentations/*`.

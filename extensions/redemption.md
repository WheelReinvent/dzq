# Extension: redemption

**Status:** part of dzq/1.0, optional.

An issuer may mark one of its gratitudes as *redeemed* (used up, for
example when it was exchanged for something). Redemption does not make a
gratitude invalid — the thank-you was still said — it is a separate fact a
verifier reports.

## Record

```
redemption digest(S) = SAID of {"d":"############################################","t":"redeem","g":"<S>"}
```

that is, Blake3-256 qb64 over exactly
`{"d":"<44 #>","t":"redeem","g":"<gratitude SAID>"}`. Anyone can recompute
it from the gratitude's SAID, so nothing has to be published besides the
KEL.

The issuer redeems by putting a digest seal `{"d": <redemption digest>}` in
an `ixn` event of its KEL. Each redemption is its own event, so that it is
visible at once.

## Verification

After a gratitude verifies (SPEC §6), `redeemed_at_sn` is the sequence
number of the first accepted event of the issuer that carries the digest
seal of `redemption digest(S)`; none if there is none.

Older DzenQ builds anchored the gratitude SAID itself as a digest seal to
redeem it. Verifiers MAY report such a seal as a redemption too (the
reference verifier and DzenQ do).

Like every KEL fact, redemption is only visible to a verifier that has a KEL
recent enough to contain it.

## Vectors

`redeemed`, and `redemption_said` in `vectors/digests.json`.

# The DzenQ implementation and dzq/1.0

DzenQ's Rust core (`rustLib/`, also built for Android, desktop and the web as
wasm) is the first implementation of this format. The spec was written from
it (`docs/formats/dzq.md`, `acdc.rs`, `verify.rs`, `challenge.rs`,
`crypto.rs`, `dzenq.rs` as of 2026-10-19), so the two agree on everything
that decides validity. This page lists what is different, and what DzenQ
should change to match the spec exactly.

Checked by: `conformance/rust/dzq_vectors.rs`, which runs every vector
through the core (copy it into `rustLib/tests/`).

## Differences

| # | Topic | DzenQ core today | dzq/1.0 | Change in DzenQ? |
|---|---|---|---|---|
| 1 | `signatures.json` in `.dzq` | written as `{}` | deprecated: ignored, not written | Stop writing it. Reading needs no change. |
| 2 | `metadata.json` | always written | optional, display only | None needed. |
| 3 | Which key a signature is checked against | any signature against any current key, index ignored | the key the index names | None for single-key identifiers (all of DzenQ). Needed before multisig. |
| 4 | Thresholds | not checked for gratitude signatures | `kt` must be met | Same as 3. |
| 5 | Failure reasons | free English text | stable codes (SPEC §6.4) | Optional: add a code next to the text. The conformance test maps text to codes for now. |
| 6 | Pre-1.0 formats | still read: sorted-keys ACDCs with a dummy SAID (`legacy_format`), test letters of 2026-10-11 with a condition in `a.i`, redemption as a digest of the SAID | not part of dzq/1.0 (redemption form allowed as MAY) | Keep reading them; never write them. |
| 7 | Source of a fresh KEL | DzenQ's watcher only | any KERI source (OOBI, witness, watcher) | Let doors and wallets use any OOBI, not only the watcher. |
| 8 | Presentations carry the issuer KEL from issuance | yes (`full_cesr` as stored) | holders SHOULD refresh it when they get a period seal | After fetching a seal, store the bundle with the issuer's current KEL; or have doors always load issuer KELs. Otherwise a sealed gratitude whose issuer rotated fails at an offline door. |
| 9 | Claim signatures | `verify_strict` | SHOULD be strict | None. (The Python reference uses OpenSSL's verify.) |
| 10 | Phone normalization adds `+38` to 10-digit numbers starting with 0 | yes | documented as DzenQ's rule | Consider making the sender's app normalize to E.164 before deriving claim keys, and dropping the country default from the format. |
| 11 | Telegram prototype (`tg/dz-309-prototype`) | does not produce `.dzq` | — | When it signs thanks, send the same bundle and a "download .dzq" link: the first proof that the format lives outside the app. |
| 12 | Archive entry whitelist | rejects unknown entries | same | None. |
| 13 | Size check of the attachment | digest only | digest (reference also checks size) | None. |

## What the conformance test does not cover

- Building the core in this repository: the core depends on DzenQ's keriox
  fork and is tested in DzenQ's CI.
- Issuing: the vectors are produced by the reference implementation; the
  test checks that DzenQ *verifies* them. To check the other direction,
  export a few DzenQ-issued `.dzq` files into `vectors/` (the issuer's
  keys need not be shared) and run the reference verifier on them.

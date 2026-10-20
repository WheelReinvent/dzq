# The DzenQ implementation and dzq/1.2

DzenQ's Rust core (`rustLib/`, also built for Android, desktop and the web as
wasm) is the first implementation of this format. The spec was written from
it (`docs/formats/dzq.md`, `acdc.rs`, `verify.rs`, `challenge.rs`,
`crypto.rs`, `dzenq.rs` as of 2026-10-19), so the two agree on everything
that decides validity. This page lists what is different, and what DzenQ
should change to match the spec exactly.

Checked by: `conformance/rust/dzq_vectors.rs`, which runs every vector
through the core (copy it into `rustLib/tests/`). Draft 1 (commit
`1cc6fd5`) passes completely in DzenQ's CI.

## Adapting DzenQ to dzq/1.3 (tag `v1.3.0`)

Pin the conformance step to tag `v1.3.0` and copy the updated
`conformance/rust/dzq_vectors.rs`. It skips the optional promises vectors
unless `DZQ_EXTENSIONS=1`; set it once step 6 is done. In order:

1. **Security finding** below: recompute every KEL event SAID (vectors
   `kel-forged-inception`, `forged-holder-kel`).
2. **Rows 14, 15**: text limits; `a.i` is one AID.
3. **Row 18**: private content — expand-check-compact, sign the compact
   form (vectors `private-*`, `gratitude-1.2*`).
4. **Row 19**: open types — accept any type generically, know the three
   base types (`types/`), read `types/<SAID>.json` from archives, `look` and
   `re` (vectors `schema-unknown`, `custom-type-*`, `envelope-*`,
   `apology*`, `promise*`, `re*`, `look-*`).
5. Issue new thank-yous as `dzq:gratitude` 1.2.0 (`EDM7gu9-…`); old ones
   stay valid.
6. Certificates: `dzq:promise` 1.1.0 — `what` (name), `ask` (what to do),
   `payload` (the code, the invite; private but not encrypted: the holder
   sees it at once). Earning by stamps → `thanks:` of the promises
   extension (dzq/1.3): «3 from me for anything» = `thanks:3/<me>:*`;
   «Dad for the room or Mom for anything» = `thanks:3/<Dad>:room+<Mom>:*`.
   Likes «👍 for a kept promise»: a gratitude with an app category such as
   `dzenq:like` — `*` does not count it. Closing early: the extension's
   close digest.

Done when every vector passes (with `DZQ_EXTENSIONS=1`).

## Security finding: forged inception events (fix first)

The keriox fork does not recompute the SAID of key events. In
`keriox_core/src/event_message/key_event_message.rs`, `compare_digest`
compares the event's own `d` with itself whenever the hash codes match,
and `verify_identifier_binding` therefore only checks `i == d`. `check_digest`
(which does recompute) is called only for replies and OOBIs.

Effect: anyone can write an `icp` with `i = d = <someone's AID>` and their
own keys. A verifier that does not already know that AID accepts it, so:

- a thank-you "from Alice", signed by Mallory, verifies (vector
  `kel-forged-inception`);
- a presentation "by Bob", signed by Mallory with a forged `holder_kel`,
  verifies (vector `forged-holder-kel`) — and, because the core keeps KELs
  first-seen, the forged KEL then stays in that verifier's database for
  Bob's AID.

Online doors that load the KEL from the watcher first are protected as
long as the watcher already holds the real KEL. Offline wallets are not.

Fix, in keriox: for every key event, `d.verify_binding(&event.to_derivation_data()?)`
(for `icp`/`dip` `to_derivation_data` already blanks both `d` and `i`);
in `verify_identifier_binding` for a self-addressing prefix, also require
that binding. Until the fork is fixed, DzenQ's core can run the same check
on each parsed event before `process_cesr`. Check whether upstream keriox
has the same code.

## Differences

| # | Topic | DzenQ core today | dzq/1.0 | Change in DzenQ? |
|---|---|---|---|---|
| 1 | `signatures.json` in `.dzq` | written as `{}` | deprecated: ignored, not written | Stop writing it. Reading needs no change. |
| 2 | `metadata.json` | always written | optional, display only | None needed. |
| 3 | Which key a signature is checked against | any signature against any current key, index ignored (a signature with index 7 passes for a one-key issuer) | the key the index names | Check the index. Harmless today for single-key issuers, but it accepts malformed groups. |
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
| 14 | Text limits (title 200, message 5000, category 64) | not checked (serde structs only) | part of validity | Check them (vector `title-too-long`). |
| 15 | `a.i` under schema 1.0.0 | parsed as a condition (pre-1.0 test letters) | one AID | Treat `a.i` as an AID, keep the old reading only for SAIDs issued before 2026-10-12 if needed (vector `condition-in-a-i`). |
| 16 | `verify_kel` "all offered events accepted" | counts events with a JSON stream reader that stops at the first `-AAB`, so it only ever sees sn 0 | every event must be accepted | Count events with the CESR parser. |
| 18 | Private content (dzq/1.1, SPEC §3.5) | not implemented: schemas 1.1.0 / 2.1.0 are unknown | issue with a salted block; verify full and compact forms | Implement: expand-check-compact before the SAID checks; sign the compact form; issue 1.1.0 / 2.1.0 (vectors `private-*`). |
| 19 | dzq/1.2: open types, `look`, `re` | only gratitude schemas known; any other `s` rejected; `blank` / `color` outside the statement; certificates in own formats `dzenq-key/1`, `dzenq-promise/1` | statements of unknown types verify (envelope, SAIDs, signature) and report the type unknown; base types `dzq:gratitude` 1.2.0, `dzq:apology`, `dzq:promise` are type documents every reader knows (SPEC §3.4, §3.8); `types/<SAID>.json` in `.dzq`; `look` and `re` in any private block (§3.7) | Accept unknown types generically (vectors `schema-unknown`, `custom-type-*`, `envelope-*`); issue gratitudes with `EDM7gu9-…`; map `blank` to `look: "dzenq:<name>"`. Certificates/promises: issue as `dzq:promise` (or DzenQ's own type); earning with stamps and closing early are DzenQ rules — the experimental extensions/promises.md shows one way, not part of dzq. |
| 17 | KELs inside one presentation | one shared database: a credential can be judged with another credential's issuer KEL, depending on order | each credential with its own bundle (plus the verifier's fresher KEL) | Order-independence; or specify a merge rule both follow. |

## What the conformance test does not cover

- Building the core in this repository: the core depends on DzenQ's keriox
  fork and is tested in DzenQ's CI.
- Issuing: the vectors are produced by the reference implementation; the
  test checks that DzenQ *verifies* them. To check the other direction,
  export a few DzenQ-issued `.dzq` files into `vectors/` (the issuer's
  keys need not be shared) and run the reference verifier on them.

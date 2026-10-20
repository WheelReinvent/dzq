# dzq and standard KERI / ACDC

dzq takes from KERI the key event log — a chain of key events with the next
key committed in advance — and from ACDC the self-addressing document. It
makes the rest optional: witnesses, watchers, registries (TEL), edges.
The reason is one decision (SPEC §0): dzq statements do not fear being used
twice, so they need no record of "already used". Most differences below
follow from it.

So dzq is not "plain ACDC with a schema". This page lists every place where
a dzq statement differs from what a generic KERI/ACDC tool expects, so that
such a tool can be taught to read them, and so that the differences are
decisions rather than accidents. (Rows say "gratitude" where they date from
dzq/1.0; they hold for every type.)

## Versions

- **KERI 1.0 / ACDC 1.0 serialization** (`KERI10JSON…`, `ACDC10JSON…`).
  The KERI/ACDC/CESR specifications were approved as v1.1 documents in
  January 2026 and describe protocol version 2.00 (`KERICAA…`, CESR 2.0).
  Deployed ecosystems (GLEIF vLEI, KERIA, did:webs) are still on 1.x, and so
  is dzq/1.0. A later major version may move to 2.00; gratitudes signed in
  1.0 stay verifiable regardless.

## Differences

| # | dzq/1.0 | Standard ACDC / KERI | Why | Effect on a generic tool |
|---|---|---|---|---|
| 1 | Issuance is a **signature attached to the ACDC** (`-A##`), valid at once; no TEL `iss` event. | Issuance state lives in a TEL (registry) anchored in the KEL. | One key event per gratitude made the KEL (and every bundle) grow without bound: 163 KB per bundle after 200 thanks. | A TEL-based verifier finds no issuance event for `ri` and reports "unknown". `ri` is kept so a TEL can be added later. |
| 2 | Many gratitudes are fixed in the KEL at once by a **period close record** (`dzq-close/1`) and a Merkle tree. | No such construct. | Same as 1. | Unknown to generic tools; see extensions/periods.md. Older gratitudes (before 2026-10-12) do have their own event seal. |
| 3 | An unsealed gratitude is valid only under the issuer's **current** key. | Signature validity is tied to the key state at the anchoring event. | There is no anchoring event for open gratitudes. | A verifier must use the latest KEL it can get (SPEC §6.3). |
| 4 | **Redemption** is a digest seal of a fixed record. | Revocation is a TEL `rev` event. | No TEL (1). | Redemption is invisible to TEL tools. |
| 5 | **Conditions** in `a.dq` with a small language (`any`, `all`, leaves). | Untargeted ACDCs exist (no `a.i`), but there is no standard condition field or language. | Thanks to "whoever proves this e-mail", to groups. | A generic tool sees an untargeted ACDC with an extra attribute. |
| 6 | **Claim proofs** `dzenq-claim/1|<SAID>|<AID>` signed by one-time Ed25519 keys (hex, not CESR). | No equivalent. | Letters to addresses without any attesting server. | Specific to the letters extension. |
| 7 | Schemas are JSON Schema with `$id` = SAID, but **without the compact/expanded `oneOf`** forms for `a`. | ACDC schemas allow each section to be replaced by its SAID (compact form) for graduated disclosure. | Not needed yet. | Compact (partially disclosed) gratitudes are not possible in 1.0. Planned with selective disclosure. |
| 8 | No `u` (salt), no `e` (edges), no `r` (rules) sections. | Optional in ACDC. | Not needed. | None. |
| 9 | Verifiers require the **canonical byte form** (SPEC §3.2), not only a matching SAID. | SAIDs are checked over the bytes as received. | One gratitude, one byte string; simpler for implementers of other languages. | Stricter; standard-produced ACDCs with the same field order and compact JSON pass. |
| 10 | Close-record "SAID" is a plain Blake3 digest of the record bytes (no `d` field in the record). | SAIDs are self-addressing. | Historical. | Named "digest" in this spec. |
| 11 | Period seal proof bytes are JSON arrays of integers. | — | Historical (serde default). | A hex form may be added in a minor version. |
| 12 | Media type `application/vnd.dzenq.gratitude+zip` for `.dzq`. | — | — | Provisional, unregistered. |
| 13 | No witnesses by default; KELs are kept by watchers that refuse forks. | Witness receipts give accountable duplicity detection. | Simplicity for a consumer app. | A verifier relies on the "first seen" view of the KEL source it uses. |

## Not differences

These follow the standards as they are and need nothing special:

- AIDs, KEL events (`icp`, `rot`, `ixn`), pre-rotation, abandonment
  (rotation to an empty `n`), Ed25519 keys and indexed signatures, Blake3-256
  SAIDs, CESR text encoding. The reference verifier's KEL code is checked
  against KERI events signed by keripy (`reference/python/tests/keripy_multisig_kel.cesr`).
- The SAID algorithm for the ACDC and its attribute block.
- Untargeted ACDCs (no `a.i`).

## Open work

- Run gratitudes through an unmodified KERI library (keripy, upstream
  keriox) and record the result here. DzenQ builds on a keriox fork
  (`WheelReinvent/keriox`, branch `dzenq-patches`); according to DzenQ's
  architecture notes the patches cover escrow, delegated inception,
  inception anchors and browser storage. A gratitude verifier should not
  depend on any of them; the vectors are meant to show that.
- Selective disclosure (#7) before any public pilot: gratitudes are
  irrevocable, and what is signed without it stays without it.
- Decide on KERI/ACDC 2.00 and CESR 2.0 for dzq/2.

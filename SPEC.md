# dzq/1.0 — Signed gratitude

**Status:** draft 1 (2026-10-19). Editors: the DzenQ team.
**This version:** `dzq/1.0`. The text is under CC BY 4.0, the code and vectors under Apache-2.0.

A *gratitude* (a thank-you) is a small file in which one person states, and
signs, that they are grateful to another person — or to whoever meets a
condition. Anyone can check that file later, offline, without asking the
app that made it. This document says what the file contains, how it is
signed and how to check it, so that any application can write and read
gratitudes. DzenQ is the first implementation, not the owner of the format.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as in
RFC 2119 / RFC 8174.

## Contents

1. [What dzq/1.0 is](#1-what-dzq10-is)
2. [Building blocks](#2-building-blocks)
3. [The gratitude credential](#3-the-gratitude-credential)
4. [Conditions](#4-conditions-adq)
5. [The credential bundle](#5-the-credential-bundle)
6. [Verification](#6-verification)
7. [The `.dzq` file](#7-the-dzq-file)
8. [Extensibility and versions](#8-extensibility-and-versions)
9. [Security considerations](#9-security-considerations)
10. [Conformance](#10-conformance)

Extensions, each optional: [letters](extensions/letters.md) (claim keys for
thanks sent to an e-mail or phone), [periods](extensions/periods.md)
(sealing many thanks with one key event), [redemption](extensions/redemption.md),
[presentation](extensions/presentation.md) (proving to a door that you hold
gratitudes). How this relates to standard KERI/ACDC:
[docs/keri-acdc-alignment.md](docs/keri-acdc-alignment.md). Where DzenQ
today differs from this text: [docs/dzenq-implementation.md](docs/dzenq-implementation.md).

---

## 1. What dzq/1.0 is

A gratitude is an [ACDC](https://trustoverip.github.io/tswg-acdc-specification/)
(Authentic Chained Data Container, version 1 serialization) issued by a
[KERI](https://trustoverip.github.io/tswg-keri-specification/) identifier and
signed with its key. It travels as a **credential bundle**: the ACDC, the
signature, and the issuer's key event log (KEL), so that a verifier needs
nothing else. On disk it is a **`.dzq` file**, a ZIP archive around the bundle.

The core (sections 2–7) is everything needed to issue a valid gratitude and
to check one. A core gratitude is valid by itself: it does not need any
extension, server, registry or network.

Out of scope of dzq/1.0: how keys are stored or recovered, how files are
delivered, any server API, the meaning of categories, certificates, stamps,
doors and other application features built on gratitudes.

### 1.1 Roles

- **Issuer** — the identifier that says thank you and signs.
- **Recipient** — an identifier (AID) named in the gratitude, *or*
- **Condition** — a rule saying who may hold it (section 4).
- **Holder** — whoever keeps the file and may present it.
- **Verifier** — any software that checks a gratitude.

## 2. Building blocks

| Thing | dzq/1.0 uses |
|---|---|
| Identifiers | KERI 1.0 AIDs, self-addressing (`E…`), Ed25519 keys (`D…`) |
| Key history | KERI 1.0 KEL, JSON events (`KERI10JSON…`), CESR text attachments |
| Digests | Blake3-256, CESR qb64 (`E` + 43 chars) |
| Signatures | Ed25519 |
| Credential | ACDC, version string `ACDC10JSON<size>_`, JSON |

**SAID.** A self-addressing identifier of a JSON object is computed by
replacing its `d` field with 44 `#` characters, serializing (section 3.2),
hashing the UTF-8 bytes with Blake3-256 and encoding the 32-byte digest as
CESR qb64: `"E" + base64url(0x00 ‖ digest)[1:]` (44 characters).

**Issuer profile.** In dzq/1.0 the issuer's KEL MUST consist of `icp`, `rot`
and `ixn` events of a non-delegated identifier, with simple (hex number)
thresholds and Ed25519 keys. Witnesses are allowed by KERI but are not
required by dzq/1.0; a verifier that does not process witness receipts MAY
treat a witnessed KEL as unsupported. The DzenQ profile is one current key,
one pre-rotated next key, no witnesses.

## 3. The gratitude credential

### 3.1 Fields

Top level, in this order: `v, d, i, ri, s, a`.

| Field | Content |
|---|---|
| `v` | `ACDC10JSON` + size of the serialized ACDC in bytes (6 lowercase hex digits) + `_` |
| `d` | SAID of the whole ACDC (3.3) |
| `i` | issuer AID |
| `ri` | identifier of the issuer's credential registry. Verifiers MUST NOT require it to resolve. |
| `s` | SAID of the schema (3.4) |
| `a` | attribute block, below |

Attribute block `a`, in this order (absent optional fields are omitted, not `null`):

| Field | Required | Content |
|---|---|---|
| `d` | yes | SAID of the attribute block |
| `i` | schema 1.0.0 only | recipient AID |
| `dq` | schema 2.0.0 only | condition (section 4), at most 65 536 bytes |
| `dt` | yes | issuance time, RFC 3339 |
| `title` | yes | at most 200 characters |
| `message` | yes | at most 5000 characters |
| `category` | yes | at most 64 characters (8.3) |
| `attachment` | no | `{"d", "filename", "mime_type", "size"}`, in this order: lowercase hex Blake3-256 of the file, file name, media type, size in bytes |

A gratitude under schema 1.0.0 MUST have `a.i` and MUST NOT have `a.dq`;
under 2.0.0 the reverse. No other fields are allowed at any level.

`dt` is what the issuer states; it is not a trusted timestamp. Order in time
comes from the issuer's KEL (section 6 and the periods extension).

### 3.2 Canonical serialization

The bytes that are hashed and signed are the **canonical serialization**:
JSON with the field order of 3.1, no whitespace between tokens, UTF-8, and
strings escaped minimally: only `"`, `\` and control characters
U+0000–U+001F are escaped (`\b \f \n \r \t` short forms, others as
`\u00XX` with lowercase hex); all other characters, including non-ASCII,
appear as themselves. `size` is a JSON integer.

A verifier MUST reject a credential whose bytes are not exactly the
canonical serialization of its content (vectors `non-canonical*`). This
rules out two byte strings for one gratitude.

### 3.3 Computing the SAIDs

1. `a.d` := SAID of `a` (with `a.d` replaced by 44 `#`).
2. With `a.d` set, put 44 `#` in `d` and `ACDC10JSON000000_` in `v`;
   serialize; `size` := the byte length; set `v` := `ACDC10JSON<size>_`.
   (The placeholder has the same length, so the size is final.)
3. `d` := Blake3-256 qb64 of the serialization with `d` still 44 `#`.

### 3.4 Schemas

The schemas are JSON Schema documents whose `$id` is their own SAID. They
are published byte for byte in [`schemas/`](schemas/). A verifier compares
`s` with the SAIDs below; it never needs to fetch a schema.

| Schema | Version | SAID |
|---|---|---|
| [gratitude.schema.json](schemas/gratitude.schema.json) — to one AID | 1.0.0 | `EHJJvD_pHa1kHRWiQq9o1KxNHNpnFpArKmGGltmDjTav` |
| [gratitude-condition.schema.json](schemas/gratitude-condition.schema.json) — to a condition | 2.0.0 | `EL3ntXZJeGkmy1w43X19vtv9J5dGTiHjqwxpEKtZRSMZ` |
| [binding.schema.json](schemas/binding.schema.json) — not a gratitude; used by DzenQ's identity binding | 1.0.0 | `ED-ubFgDExNNMYg9Q_Y_VmvJorQpAXGbGX8x8urN7EVo` |

A schema's SAID is Blake3-256 over the file with `$id` set to 44 `#`.
The schema text is normative only through its SAID and section 3.1; where
they differ, section 3.1 wins.

## 4. Conditions (`a.dq`)

A gratitude to a condition (schema 2.0.0) names no person. `a.dq` says who
may hold it; whoever proves it holds it, and if ten people prove it, all ten
hold it.

```
condition := "any(" condition ("," condition)* ")"
           | "all(" condition ("," condition)* ")"
           | leaf
leaf      := AID                         [A-Za-z0-9_-]+
           | "claim:" 64 hex digits      a one-time Ed25519 claim key (letters extension)
           | "commitment:" non-empty     older binding flow (deprecated)
           | kind ":" value              kind = [a-z0-9-]+, value has no whitespace , ( )
```

- Whitespace around items is allowed; the canonical text has none.
- Nesting depth is at most 8 levels below the top.
- `any` holds when at least one item holds; `all` when every item holds
  (and it has at least one).
- `claim:` hex is compared in lower case.
- **A leaf of a kind the verifier does not know is kept and never met.**
  `any(txn:…, <AID>)` can still be met through the AID; `all(txn:…, …)`
  cannot be met at all. This is how new kinds are added without a new
  format (section 8).
- `commitment:` leaves are not met by dzq/1.0 verifiers.
- A condition that does not parse is met by nobody. The credential itself
  still verifies (its signature is fine); it simply has no holder.

How a leaf is *proved* is up to the context: an `AID` leaf by the holder's
signature (presentation extension), a `claim:` leaf by a claim proof
(letters extension).

## 5. The credential bundle

```
bundle := ACDC  signatures  KEL
```

- `ACDC` — the canonical serialization (section 3.2).
- `signatures` — a CESR controller-signature group: `-A` + count (2 base64
  digits) + that many indexed Ed25519 signatures over the ACDC bytes. Code
  `A` + one base64 digit index (88 characters each). The index names the key
  in the issuer's key list. Issuers SHOULD attach exactly one signature,
  `-AAB` + `AA…`.
- `KEL` — the issuer's KEL as a CESR text stream: each event's JSON
  followed by its attachments (at least its own `-A##` signatures). It MUST
  contain the issuer's events up to at least the establishment event whose
  key signed the gratitude. It MAY contain later events (a holder MAY
  refresh it).

The bundle is UTF-8 text. As a separate file its extension is `.acdc` and
its media type `application/cesr`.

## 6. Verification

### 6.1 Inputs

The bundle; optionally a **fresher KEL** of the issuer, from any KERI source
(an OOBI, a KERI witness or watcher, the issuer, DzenQ's watcher — any of
them; the KEL is self-certifying, so the source does not need to be trusted);
optionally a **period seal** (periods extension).

### 6.2 Steps

A verifier MUST perform these steps in order and stop at the first failure,
reporting its code (6.4).

1. **Split** the bundle: the first JSON value is the ACDC; if it is followed
   by `-A`, read the signature group; the rest is the KEL. — `format`
2. **Canonical form**: the ACDC starts with `{"v":`, parses, has exactly the
   fields of 3.1 with the right types, and re-serializes to the same bytes.
   — `canonical` / `schema`
3. **Schema**: `s` is one of the gratitude SAIDs of 3.4 and `a.i` / `a.dq`
   match it. — `schema`
4. **SAIDs**: `a.d` recomputes; the size in `v` equals the byte length;
   `d` recomputes. — `said`
5. **Issuer KEL**: process the KEL (the fresher one if given, else the one
   in the bundle) by KERI rules: every event's SAID and version size
   recompute; `icp` is signed by its keys; each `rot` is signed by new keys
   whose digests were committed in the previous `n` list; each `ixn` is
   signed by the current keys; sequence numbers and prior digests chain.
   Only accepted events count; the log ends at the first event that is not
   accepted. There must be at least an accepted inception of `i`. — `kel`
6. **Signature present.** — `no-signature`
7. **Signed by whom, when** — exactly one of:
   - **anchored**: an `ixn`/`rot` of the issuer at sequence number *k*
     carries an event seal `{"i": <gratitude SAID>, "s", "d"}`; a signature
     MUST verify with the key its index names among the keys current at *k*.
     Result: `sealed`, `anchored_at_sn = k`. — else `signature`
   - **sealed period** (only if a period seal was supplied and the
     gratitude is not anchored): see the periods extension; the signature
     MUST verify with a key current at some point of that period. Result:
     `sealed`, `anchored_at_sn` = the closing event. — else `seal` / `signature`
   - **open**: a signature MUST verify with the issuer's **current** keys
     (those of the last accepted establishment event; none if the
     identifier was abandoned). — else `not-current`
8. **Redemption** (informative result, not a failure): the redemption
   extension.

The gratitude is **valid** when all steps pass. The recipient is `a.i`
(schema 1.0.0) or the condition `a.dq` (2.0.0); who *holds* it is a separate
question (section 4, presentation extension).

### 6.3 What "valid" means: offline and fresh

A signature by the current key is only as current as the KEL the verifier
has. dzq/1.0 is honest about it:

| Result | Meaning |
|---|---|
| valid, `sealed` | Final. The gratitude is pinned in the issuer's KEL; later rotations do not affect it. |
| valid, not sealed, checked with the bundle's KEL only | **Offline result.** True as of the KEL in the file (`issuer_kel_sn`). If the issuer rotated keys since and never sealed it, it is void, and this verifier cannot know. |
| valid, not sealed, checked with a fresh KEL | True as of that KEL. |

After a rotation, unsealed signatures by older keys are void, whatever date
they carry: KERI orders events, not clocks. Verifiers that act on a
gratitude (open a door, grant something) SHOULD load a fresh KEL or require
`sealed`; verifiers that only display MAY show offline results, and SHOULD
say that they are offline results. Issuers SHOULD seal before rotating
(periods extension).

### 6.4 Result

A verifier reports at least: `valid`; on failure one `code`:

| Code | Meaning |
|---|---|
| `format` | not a bundle: no JSON, broken signature group |
| `canonical` | ACDC bytes are not canonical (or a pre-1.0 legacy credential) |
| `schema` | wrong or unknown schema, missing or extra fields, wrong types |
| `said` | a SAID or the version size does not recompute — content changed |
| `kel` | the issuer's KEL is missing, unreadable or not accepted |
| `no-signature` | no signature |
| `signature` | the signature does not match the keys it must match |
| `not-current` | not sealed, and not signed by the issuer's current keys |
| `seal` | a supplied period seal does not prove the gratitude |

and on success `said`, `issuer`, `recipient`, `sealed`, `anchored_at_sn`,
`redeemed_at_sn`. Implementations MAY add human-readable reasons.

## 7. The `.dzq` file

A ZIP archive (deflate or stored) with these entries:

| Entry | Required | Content |
|---|---|---|
| `credential.acdc` | yes | the bundle (section 5), UTF-8 |
| `metadata.json` | no | for display only, never trusted: `{id, title, message, issuedAt, issuer_aid, recipient_aid}` |
| `assets/<file name>` | no | the file named by `a.attachment` |
| `signatures.json` | no | **deprecated**; written as `{}` by DzenQ before dzq/1.0. Readers ignore it; writers MUST NOT write it. |

- Writers MUST NOT add other entries in dzq/1.0. Readers MUST reject
  archives with other entries (`unexpected entry`), so that a future
  version that adds entries is not silently half-read.
- Limits a reader MUST enforce: archive ≤ 25 MB, ≤ 20 entries, each entry
  ≤ 20 MB, ≤ 25 MB uncompressed in total. Names MUST NOT be absolute, use
  `\`, contain `..` path segments or a drive prefix; an asset name MUST NOT
  be empty, start with `.`, contain `/ \ : NUL` or `..`, or exceed 255 bytes.
- A reader MUST verify the credential before it writes anything to disk,
  and MUST extract only the asset named in `a.attachment.filename`, only if
  its Blake3-256 equals `a.attachment.d`.
- `metadata.json` MUST NOT be used for any decision. If it disagrees with
  the credential, the credential wins (vector `lying-metadata`).

File extension `.dzq`. Media type `application/vnd.dzenq.gratitude+zip`
(provisional; registration with IANA is planned).

## 8. Extensibility and versions

### 8.1 What cannot change within dzq/1.x

The fields of 3.1, the canonical serialization, the SAID rules and the
schema SAIDs. A gratitude signed today stays verifiable forever; a new
attribute means a new schema with a new SAID, announced in a new minor
version, while verifiers keep accepting the old ones.

### 8.2 Unknown things

- Unknown fields in a credential: reject (`schema`).
- Unknown schema SAID: reject (`schema`) — or verify it under a newer
  version of this document that defines it.
- Unknown condition leaf kinds: keep, never met (section 4).
- Unknown archive entries: reject (section 7).
- Unknown CESR attachment groups in a KEL: verifiers MAY skip groups whose
  size they know (receipts, first-seen replay couples, seal source couples)
  and MUST otherwise stop.

### 8.3 Categories and condition kinds from other applications

- `a.category` is free text chosen by the issuer; its meaning is the
  issuer's. Values without `:` are general words (`help`, `team`).
  Application-specific categories SHOULD be prefixed with a reverse domain
  or app name and a colon (`org.example.shop:coffee`), so apps do not
  collide. No verifier decision depends on the category.
- New condition kinds: a kind name of `[a-z0-9-]+`. Experimental kinds
  SHOULD start with `x-`. A kind becomes standard when a version of this
  document defines how it is proved; until then every verifier treats it as
  never met.

### 8.4 Version names

`dzq/MAJOR.MINOR`. Minor versions only add (schemas, condition kinds,
extensions, archive entries announced with a version marker). A major
version may change the serialization; it will be a new schema family and
a new file signature.

## 9. Security considerations

- **Stolen keys.** Whoever holds the issuer's current key can issue
  gratitudes in their name until the issuer rotates. Unsealed gratitudes
  signed with the old key become void at the rotation (6.3) — this is
  intended. Gratitudes sealed before the rotation stay valid.
- **Stale KEL.** Offline verification cannot see rotations it was not
  given. See 6.3.
- **Forked KELs.** Two different events at one sequence number are
  duplicity. A verifier keeps the first it saw. Gratitudes are only as
  strong as the verifier's view of the KEL; sources that keep "first seen"
  logs (KERI watchers, witnesses) protect against a thief rewriting
  history after stealing recovery words.
- **Conditions to addresses** (letters extension) are held by whoever
  receives the claim key through that address, including someone who has
  taken over the address. The issuer accepts that risk when choosing an
  address over an AID.
- **Privacy.** A gratitude is not encrypted. Title, message, recipient and
  category are readable by anyone who has the file. Do not send a `.dzq`
  where you would not send its text. Selective disclosure is planned for a
  later version (docs/keri-acdc-alignment.md).
- **Archives** are untrusted input: enforce section 7 before anything else.
- **Timestamps** in `dt` are claims, not proofs.

## 10. Conformance

- **Issuer** — produces credentials that the reference verifier accepts.
- **Verifier** — reproduces every expected result in [`vectors/`](vectors/):
  credentials, archives, conditions and (if it implements the extension)
  presentations.
- **Reader** — opens `.dzq` files safely (section 7) and shows them, with
  the offline caveat of 6.3.

The [reference verifier](reference/python/) (Python, depends only on an
Ed25519 library) and the DzenQ core both run the vectors. The vectors are
produced by [`tools/gen_vectors.py`](tools/gen_vectors.py) from fixed seeds.

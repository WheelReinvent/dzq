# dzq/1.3 — Signed statements between people

**dzq** (pronounced *dee-zik*) is a file format for signed statements from
one person to another: a thank-you, an apology, a notice, an achievement —
whatever an app defines. The name comes from DzenQ, the first application
that used it; DzenQ is the first implementation, not the owner of the
format.

**Status:** published 2026-10-20, git tag `v1.3.0`. Editors: the DzenQ team.
**This version:** `dzq/1.3` — 1.3 gives the promise `ask` and `payload`
(3.8), replaces the condition language with URL-style conditions in `a.req`
— one or a list; a condition may ask for statements the holder shows
(section 4) — and makes [promises](extensions/promises.md) (usable, closing
early) an optional extension. Earlier:
1.1 added private content (3.5); 1.2 opened
types to everyone (3.6: type documents, unknown types still verify), adds
two general fields, `look` and `re` (3.7), and a library of base types:
gratitude, apology, promise (3.8). Everything valid under an
earlier 1.x stays valid. The text is under CC BY 4.0, the code and vectors
under Apache-2.0.

A dzq file is a small, signed statement: one person says something to
another person — or to whoever meets a condition — and signs it. Anyone can
check the file later, offline, without asking the app that made it — and
without a ledger, a registry or a server, because dzq leaves out the one
problem that needs them: double spending (section 0). This document says
what the file contains, how it is signed and how to check it, so that any
application can write and read it.

Every dzq file has two layers:

- the **envelope**: who says it, to whom (a person or a condition), when,
  the signature and the signer's key history. The envelope is the same for
  every kind of statement, and so is its verification;
- the **type**: what is being said. The type is named by `s`, the SAID of a
  **type document**, which lists the fields and which of them are private.
  Anyone can write a type document (3.6); dzq publishes three **base
  types** every reader knows — gratitude, apology, promise (3.8) — none of
  them special. A verifier that does not know a type still
  checks the envelope, the SAIDs and the signature.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as in
RFC 2119 / RFC 8174.

## Contents

0. [Why dzq, and is it for you?](#0-why-dzq-and-is-it-for-you)
1. [What dzq is](#1-what-dzq-is)
2. [Building blocks](#2-building-blocks)
3. [The statement: envelope and type](#3-the-statement-envelope-and-type)
4. [Conditions](#4-conditions-areq)
5. [The credential bundle](#5-the-credential-bundle)
6. [Verification](#6-verification)
7. [The `.dzq` file](#7-the-dzq-file)
8. [Extensibility and versions](#8-extensibility-and-versions)
9. [Security considerations](#9-security-considerations)
10. [Conformance](#10-conformance)

Extensions, each optional: [letters](extensions/letters.md) (claim keys for
statements sent to an e-mail or phone), [periods](extensions/periods.md)
(sealing many statements with one key event), [redemption](extensions/redemption.md),
[presentation](extensions/presentation.md) (proving to a door that you hold
them), [looks](extensions/looks.md) (a shared look document),
[promises](extensions/promises.md) (when a promise is usable).
How this relates to standard KERI/ACDC:
[docs/keri-acdc-alignment.md](docs/keri-acdc-alignment.md). Where DzenQ
today differs from this text: [docs/dzenq-implementation.md](docs/dzenq-implementation.md).

---

## 0. Why dzq, and is it for you?

**Not every interaction between people is money.** Banks and blockchains
make transactions unforgeable and verifiable, but nearly all of their
complexity — global ordering, consensus, ledgers, registries — goes into
one problem: that nothing is spent twice. A developer who wants to make a
thank-you, an apology or an official statement unforgeable today chooses
between a ledger whose features they mostly do not need and simple
signatures that hand a monopoly to whoever holds the register of keys (a
certificate authority, a signing platform). The decentralised alternative,
PGP, lost on key management: a lost or stolen key meant a lost identity.

**KERI found the balance.** A key event log kept as a chain, with the hash
of the next key committed in advance, removed the need for a central
authority and made key rotation safe. Around it grew witnesses, watchers
and status registries (TEL) — because KERI, too, guards against things
happening twice: two versions of a key history (duplicity), and a
credential used or revoked.

**dzq takes from KERI the key event log and self-addressing documents, and
makes the rest optional.** It is for statements between people where what
matters is *who said it* and *that it is unchanged* — not *how many times
it was shown*. A thank-you shown twice does not become two thank-yous.

One question decides whether your use case fits:

> **Would anything break if the same statement were shown twice — to two
> different people, or a year later?**

- **No** → dzq fits: a thank-you, an apology, an official statement, a
  notice on a board, an achievement, "I was there", a recommendation.
- **Yes** → dzq does not fit: a balance, a ticket, a one-time coupon, a vote,
  a place in a queue. Those need a place that records "already used"
  (a KERI TEL, vLEI, a ledger, your database). dzq has none, on purpose:
  **dzq does not prevent double spending.**

Leaving that out is what lets a dzq statement need only a signature and
the signer's key history, carried in the file — and it is no easier to
forge for it: nobody but the issuer can make it, nobody can change it, and
anyone can check it offline.

What dzq does **not** leave out is the key history's own "twice": someone
who steals a key could try to show two versions of the issuer's history.
That is a problem about the signer, not about the statement, and dzq
handles it the KERI way — first seen wins, offline results say they are
offline, and witnesses or watchers remain available to issuers who want
them (6.3, section 9).

To keep the format small, dzq will not add:

- **registries or revocation lists** (TEL); an issuer can only hint, in its
  own key history, that it considers something redeemed or closed
  (extensions) — a hint for the honest, not a guarantee;
- **graphs of statements**: a statement may name one other it answers
  (`re`, 3.7), as a hint. The one link that is checked is a condition that
  asks the holder to show other statements ("three thank-yous from me",
  section 4) — thank now, repay later — and it never consumes them;
- **chains of trust or delegation**: a statement says what its issuer says,
  nothing about who the issuer is to anyone else;
- **free structure**: every type uses the same envelope and the same
  verification; a type adds fields, never rules;
- **mandatory infrastructure**: no server, witness or network is needed to
  write or check a statement.

If you need any of these, use KERI and ACDC directly (dzq is a profile of
them: [docs/keri-acdc-alignment.md](docs/keri-acdc-alignment.md)) — and
keep dzq for the gestures around them.

## 1. What dzq is

A dzq statement is an [ACDC](https://trustoverip.github.io/tswg-acdc-specification/)
(Authentic Chained Data Container, version 1 serialization) issued by a
[KERI](https://trustoverip.github.io/tswg-keri-specification/) identifier and
signed with its key. It travels as a **credential bundle**: the ACDC, the
signature, and the issuer's key event log (KEL), so that a verifier needs
nothing else. On disk it is a **`.dzq` file**, a ZIP archive around the bundle.

The core (sections 2–7) is everything needed to issue a valid statement and
to check one. A core statement is valid by itself: it does not need any
extension, server, registry or network.

Out of scope: how keys are stored or recovered, how files are delivered,
any server API, the meaning of categories and of types' fields, and
application features built on top (stamps, doors). See also section 0.

In the rest of this document, *statement* and *credential* mean the same
thing; *gratitude* means a statement of the `dzq:gratitude` base type (or
of its dzq/1.0–1.1 schemas).

### 1.1 Roles

- **Issuer** — the identifier that makes the gesture and signs.
- **Recipient** — an identifier (AID) named in the credential, *or*
- **Condition** — a rule saying who may hold it (section 4).
- **Holder** — whoever keeps the file and may present it.
- **Verifier** — any software that checks a credential.

## 2. Building blocks

| Thing | dzq uses |
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

**Issuer profile.** In dzq the issuer's KEL MUST consist of `icp`, `rot`
and `ixn` events of a non-delegated identifier, with simple (hex number)
thresholds and Ed25519 keys. Witnesses are allowed by KERI but are not
required by dzq (section 0): they protect against a forked key history,
which an issuer may want, but no statement needs. A verifier that does not process witness receipts MAY
treat a witnessed KEL as unsupported. The DzenQ profile is one current key,
one pre-rotated next key, no witnesses.

## 3. The statement: envelope and type

### 3.1 Fields

**Envelope.** Every dzq statement has, at the top level and in this order,
`v, d, i, ri, s, a`:

| Field | Content |
|---|---|
| `v` | `ACDC10JSON` + size of the serialized ACDC in bytes (6 lowercase hex digits) + `_` |
| `d` | SAID of the whole ACDC (3.3) |
| `i` | issuer AID |
| `ri` | identifier of the issuer's credential registry. Verifiers MUST NOT require it to resolve. |
| `s` | SAID of the type document (3.6) or of a dzq/1.0–1.1 schema (3.4) |
| `a` | attribute block |

The attribute block `a` holds, in this order:

| Field | Required | Content |
|---|---|---|
| `d` | yes | SAID of the attribute block |
| `i` | one of `i`, `req` | recipient: one AID |
| `req` | one of `i`, `req` | what it takes to hold it: a condition or a list of conditions (section 4), at most 65 536 bytes |
| `dt` | yes | issuance time, RFC 3339 |
| *public fields* | per type | the type's public fields (3.6) |
| `c` | when the type has private fields | the private block (3.5), always last |

Field names of a type are `[a-z][a-z0-9_]{0,31}`. The names `d`, `i`, `req`, `dq`,
`dt`, `c`, `u`, `look`, `re`, `from`, `to`, `since` and `count` are
reserved. Envelope names are short (`i`, `req`, `dt`); a type's own fields
are words (`category`, `message`). Values are strings, integers
(|n| ≤ 2^53), booleans, lists and objects of these, nested at most 8 deep:
**no floats** (one number, two spellings) and **no `null`** (absent fields
are omitted). The whole ACDC is at most 256 KB.

`a.i` is always a single AID, never a condition (vector `condition-in-a-i`).
`dt` is what the issuer states; it is not a trusted timestamp. Order in
time comes from the issuer's KEL (section 6 and the periods extension).

Which public and private fields a statement has is up to its type: the
base types (3.8) or your own (3.6). Text limits are counted in Unicode
characters and are part of validity when the verifier knows the type
(vector `title-too-long`). A field of kind `attachment` is
`{"d", "filename", "mime_type", "size"}`, in this order: lowercase hex
Blake3-256 of the file, file name, media type, size in bytes.

### 3.2 Canonical serialization

The bytes that are hashed and signed are the **canonical serialization**:
JSON with the field order of 3.1, no whitespace between tokens, UTF-8, and
strings escaped minimally: only `"`, `\` and control characters
U+0000–U+001F are escaped (`\b \f \n \r \t` short forms, others as
`\u00XX` with lowercase hex); all other characters, including non-ASCII,
appear as themselves. `size` is a JSON integer.

A verifier MUST reject a credential whose bytes are not exactly the
canonical serialization of its content (vectors `non-canonical*`). This
rules out two byte strings for one credential.

### 3.3 Computing the SAIDs

1. `a.d` := SAID of `a` (with `a.d` replaced by 44 `#`).
2. With `a.d` set, put 44 `#` in `d` and `ACDC10JSON000000_` in `v`;
   serialize; `size` := the byte length; set `v` := `ACDC10JSON<size>_`.
   (The placeholder has the same length, so the size is final.)
3. `d` := Blake3-256 qb64 of the serialization with `d` still 44 `#`.

### 3.4 Fixed SAIDs

Base type documents are published byte for byte in [`types/`](types/),
older schemas in [`schemas/`](schemas/), each with `$id` = its own SAID (Blake3-256 over the
file with `$id` set to 44 `#`). A verifier recognises these by SAID; it
never needs to fetch them.

| Type | Document | Version | SAID |
|---|---|---|---|
| `dzq:gratitude` | [types/gratitude.json](types/gratitude.json) — base type (3.8) | 1.2.0 | `EA7UscxbMPT20L2iL0_rh1kyV_atIttXW3erkpAKqsHy` |
| `dzq:apology` | [types/apology.json](types/apology.json) — base type (3.8) | 1.0.0 | `EPAEJEeoWrF34_fWkqnTSHlhUPddcHsAYrPKBDhdULzi` |
| `dzq:promise` | [types/promise.json](types/promise.json) — base type (3.8) | 1.1.0 | `ENdXpl_T_qnJbaY59IOIHOtlAUyqo3gd6G4VhH_P8TCo` |
| gratitude | [gratitude.schema.json](schemas/gratitude.schema.json) — dzq/1.0, all public, to one AID | 1.0.0 | `EHJJvD_pHa1kHRWiQq9o1KxNHNpnFpArKmGGltmDjTav` |
| gratitude | [gratitude-condition.schema.json](schemas/gratitude-condition.schema.json) — dzq/1.0, all public, to a condition | 2.0.0 | `EL3ntXZJeGkmy1w43X19vtv9J5dGTiHjqwxpEKtZRSMZ` |
| gratitude | [gratitude-private.schema.json](schemas/gratitude-private.schema.json) — dzq/1.1, to one AID | 1.1.0 | `EMI0LpKv73h125n5PgJIYxXc1u3QBvkvWbt3hl9FvKn_` |
| gratitude | [gratitude-private-condition.schema.json](schemas/gratitude-private-condition.schema.json) — dzq/1.1, to a condition | 2.1.0 | `EMa9OBQr5dKKmPH2hLNViB8QVEN1m6GVlVJq2Tvsildc` |
| — | [look.schema.json](schemas/look.schema.json) — the look/1 document (extension), not a statement | 1.0.0 | `EIPQeKyOu9UNczhgujDJwHEYA1SP1CuKen9pRt8PxZfv` |
| — | [binding.schema.json](schemas/binding.schema.json) — not a dzq type; DzenQ's identity binding, published for reference | 1.0.0 | `ED-ubFgDExNNMYg9Q_Y_VmvJorQpAXGbGX8x8urN7EVo` |

The dzq/1.0–1.1 layouts are fixed: 1.0.0 / 2.0.0 have `title`, `message`,
`category`, optional `attachment` in `a` (in this order), no `c`, and use
`a.i` (1.0.0) or `a.dq` (2.0.0); 1.1.0 / 2.1.0 have `category` in `a` and
`title`, `message`, optional `attachment` in `c`. Their schema files carry
DzenQ-era titles ("DzenQ Gratitude"); those are part of the signed SAIDs
and stay. Their `a.dq` holds a single condition of section 4; the
pre-1.3 `any(…)` / `all(…)` / `claim:` forms are no longer read (such a
statement verifies but has no holder). New thank-yous use `dzq:gratitude`
1.2.0.

### 3.5 Private content

A type may put some of its fields in a **private block** `a.c`, which can
be shown, or replaced by its SAID, without changing the statement's SAID or
signature. The holder keeps the full form; a verifier can be shown the
compact one and still check everything except the hidden words.

| Where | Fields, in this order |
|---|---|
| `a` | `d`, `i` or `req`, `dt`, the public fields, `c` |
| `a.c` | `d`, `u`, the private fields, optional `look`, optional `re` |

- `a.c.u` is a **salt**: 128 random bits, CESR qb64 with code `0A` (24
  characters). It is required; without it a short text could be found by
  guessing against `a.c.d`. Issuers MUST draw it from a cryptographic random
  source and never reuse it.
- **Full form**: `a.c` is the block object. **Compact form**: `a.c` is the
  string `a.c.d`.
- **All SAIDs, the version size and the signature are computed over the
  compact form** (3.3 applied to the compact form, after `a.c.d` := SAID of
  the block with its own `d` set to 44 `#`). So both forms carry the same
  `d`, `a.d`, `v` and signature: they are one statement.
- A `.dzq` file normally holds the full form. To show a statement without
  its words, the holder sends the compact form (in a `.dzq` without the
  attachment, or inside a presentation).

This is ACDC partial disclosure of a nested block with a salt (`u`).

### 3.6 Types: anyone can define one

A **type document** is a JSON Schema (draft-07) of the statement whose
`$id` is its own SAID, with a `dzq` block that lists the fields in a form
any language reads without a schema validator:

```json
"dzq": {"type": "acme:board-post", "version": "1.0.0", "to": ["aid", "condition"],
        "public":  [{"name": "area", "required": true, "max": 64}],
        "private": [{"name": "text", "required": true, "max": 2000},
                    {"name": "photo", "kind": "attachment"}]}
```

- `type` is `<source>:<name>`, both `[a-z0-9-]`, lowercase. The source is
  your app or organisation. **The source `dzq` is reserved** for the base
  types; a reader MUST ignore a document that claims it unless its SAID is
  listed in 3.4.
- `version` is `MAJOR.MINOR.PATCH`. A changed document is a new SAID; old
  statements keep their SAID and stay valid.
- `to`: `aid`, `condition`, or both — whether `a.i` and/or `a.req` is used.
- `public` / `private`: field items `{name, required?, kind?, max?, description?}`.
  `kind` is `text` (default: a string, `max` characters at most) or
  `attachment` (a file object as in gratitude). A name is in one list only
  and is never reserved (3.1).
- The JSON Schema part says the same thing for schema-aware tools; the
  `dzq` block is normative. `make_type` in the reference builds both.

The **statement names its type by SAID** (`s`), never by name: a type
cannot be swapped after signing, and two apps can both have a
`board-post` without colliding.

A verifier that **knows** the type (a base type, configured, or carried in the
`.dzq` as `types/<SAID>.json`: section 7) also checks the fields: every
required field present, no field the type does not list, text within
`max`, files well-formed, `a.i`/`a.req` allowed by `to`. A verifier that does
**not** know it checks the envelope (3.1, 3.5), the SAIDs and the signature
— everything section 6 requires — and reports the type as unknown
(`type_known` = false). The statement is valid; the reader just cannot
vouch that the fields mean what the type says (vectors `custom-type-*`).

Writers SHOULD put fields in the order the type lists them; verifiers do
not check it (the canonical bytes are what is signed).

### 3.7 General fields: `look` and `re`

The private block of any type may end with two optional fields. Both are
**hints**: signed and private with the rest of the block, never a reason
for a statement to be valid or invalid beyond their own format.

- **`look`** = `<source>:<id>` — how the issuer wants it shown: which app
  or catalogue to ask (`[a-z0-9-]+`) and what exactly (the SAID of a look/1
  document, or a name: `dzenq:gold`). The source is required. A reader that
  does not know it shows its default. Only the pointer is standardized; a
  shared document format, look/1, is an optional extension
  ([extensions/looks.md](extensions/looks.md)).
- **`re`** = the SAID of the statement this one answers ("thank you for the
  thank-you", "sorry for…", "done — as promised"). One SAID, no kind of
  link, nothing to resolve: a reader that has the other statement may show
  them together. Nothing is verified across statements (section 0).

### 3.8 Base types

dzq publishes a small library of types for the most common gestures, in
[`types/`](types/). Every reader MUST know them, so a statement of a base
type needs nothing else to be checked in full. They are ordinary type
documents: verification treats them exactly like any other type, and none
is preferred over yours. Use one as it is, or write `myapp:gratitude` with
your own fields and carry it in your files (3.6, section 7).

| Type | Public | Private |
|---|---|---|
| `dzq:gratitude` 1.2.0 — *thank you* | `category` (≤ 64, required; 8.3) | `title` (≤ 200), `message` (≤ 5000), optional `attachment` |
| `dzq:apology` 1.0.0 — *sorry* | — | `title` (≤ 200), `message` (≤ 5000), optional `attachment` |
| `dzq:promise` 1.1.0 — *I will* | optional `until` (RFC 3339, ≤ 64) | `what` (≤ 200), optional `ask` (≤ 5000), optional `payload` (≤ 5000) |

Fields are required unless marked optional. All three may be addressed to
one AID or to a condition, and take `look` and `re` (3.7).

- An **apology** shows nothing but the envelope: who, to whom, when. For
  the recipient it proves the wrong was acknowledged; showing it to others
  exposes someone else's admission, so apps SHOULD keep it compact when
  showing it.
- A **promise** is a statement of intent: no use counter, no "used" state
  (section 0). `what` is what is promised; `ask`, what to do to earn it;
  `payload`, something of value for the holder — a code, an invite link.
  `payload` is private like the rest of the block (hidden in every compact
  copy), **not encrypted**: whoever has the full file sees it at once,
  before earning anything, and a promise to a condition is usually sent to
  everyone in it. Something that must reach a person only after they have
  earned it is sent then, as its own statement (`re` = the promise).
  `until` is the issuer's word; the optional
  [promises](extensions/promises.md) extension enforces it and adds
  closing early. Earning a promise ("after three thank-yous from me") is
  its condition: `a.req` = `dzq:gratitude?from=<me>&count=3` (section 4).

## 4. Conditions (`a.req`)

A statement to a condition names no person. `a.req` says what it takes to
hold it; whoever proves that holds it, and if ten people prove it, all ten
hold it. `a.req` is **one condition** (a string) or a **list** of them, any
one of which is enough. Each condition reads like a URL:

```
?aid=<AID>                                     the holder is this AID
?claim=<64 hex>                                the holder has this claim key (letters extension)
<type>?from=<AID>[&<field>=<value>…][&to=<AID>][&since=<time>][&count=<N>]
                                               the holder shows such statements
```

```json
"req": "?aid=<Marko>"
"req": ["?aid=<Marko>", "?aid=<Sofia>"]
"req": "dzq:gratitude?from=<Dad>&category=cleaned the room&count=3"
"req": ["dzq:gratitude?from=<Dad>&category=cleaned the room&count=3",
        "dzq:gratitude?from=<Mom>&count=5"]
"req": "dzq:apology?from=<Olena>&count=2"
"req": "dzq:gratitude?from=<Dad>&to=<Marko>&count=3"
```

**Statement conditions** (`<type>?…`) describe the statements the holder
must show, like a template; anything not given may be anything:

- `<type>` — a type name (`dzq:gratitude`, `myshop:visit`) or a type SAID.
  A verifier matches a name only for types it knows; a SAID always.
- `from` (required) — the issuer of those statements. A condition that
  accepted statements from anyone could be met with identifiers the holder
  makes up.
- `to` — their recipient (`a.i`). "Three thank-yous from Dad **to Marko**":
  only Marko can meet it.
- any other key — a **public** field of the type, compared exactly as a
  string. A category belongs to its issuer (8.3), so `category` together
  with `from` names one issuer's category.
- `since` — RFC 3339; only statements with `a.dt` at or after it.
- `count` — at least this many distinct statements (by SAID); default 1.
  Each condition counts on its own; counts of different conditions do not
  add up.

In a presentation (extensions/presentation.md) a statement condition is met
when, among the statements shown with it, at least `count` distinct ones
are valid (section 6), match, and are held by the holder **directly**
(`a.i` = holder, or `a.req` contains `?aid=<holder>`). A statement the
holder issued to itself counts only toward a statement the holder issued
too.

**Rules for all conditions:**

- Pairs are `key=value` joined by `&`; each key at most once. Keys are
  `[a-z][a-z0-9_]{0,31}`. In values only `%`, `&` and `=` are
  percent-encoded (`%25`, `%26`, `%3D`); everything else, spaces and
  non-ASCII included, is written as it is.
- `from`, `to`, `since`, `count` are reserved: no type has fields with these
  names.
- A condition that does not parse, or uses a key the verifier does not
  know in `?…` (`?txn=…`), is **never met**. Others in the list still can
  be. A statement whose conditions are all unmeetable still verifies (its
  signature is fine); it simply has no holder.
- Canonical text (used in vectors): reserved keys in the order `from`,
  `to`, the fields as written, `since`, `count`; `count=1` omitted.

How a condition is *proved* depends on the context: `?aid=` by the
holder's signature (presentation extension), `?claim=` by a claim proof
(letters extension), a statement condition by the statements shown.

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
3. **Envelope and type**: `a` follows 3.1 and, if present, `a.c` follows
   3.5 (`look` and `re` as in 3.7). If `s` is a dzq/1.0–1.1 schema of 3.4,
   `a` has exactly that layout. If the verifier knows the type document
   `s` names, the fields follow it (3.6). Otherwise `s` is a SAID and the
   type is reported unknown. — `schema`, `format` (over 256 KB)
4. **SAIDs**: if `a.c` is given in full form, `a.c.d` recomputes over the
   block; then replace the block by `a.c.d` (compact
   form). On the compact form: `a.d` recomputes; the size in `v` equals its
   byte length; `d` recomputes. — `said`

   From here on, "the ACDC bytes" means the compact form: that is what the
   signature covers. Report whether the private content was **shown** or
   **hidden**.
5. **Issuer KEL**: process the issuer's events — those of a fresher KEL
   first, if given, then those in the bundle; for each sequence number the
   first accepted event wins (KERI "first seen"). An event is accepted when
   its version string is exact for its size; it has exactly the KERI 1.0
   fields of its type in KERI order (compact JSON); **its SAID recomputes**
   (for `icp`, with both `d` and `i` set to 44 `#`; a self-addressing `i`
   must then equal `d`); `icp` is signed by its keys; each `rot` is signed
   by new keys whose digests were committed in the previous `n` list; each
   `ixn` is signed by the current keys; sequence numbers and prior digests
   chain. The log ends at the first event that is not accepted. There must
   be an accepted inception of `i`. — `kel`

   Recomputing the SAID of every event is what binds the AID to its keys.
   Without it anyone can write an inception for someone else's AID with
   their own keys (vector `kel-forged-inception`).
6. **Signature present.** — `no-signature`
7. **Signed by whom, when** — exactly one of:
   - **anchored**: an `ixn`/`rot` of the issuer at sequence number *k*
     carries an event seal `{"i": <statement SAID>, "s", "d"}`; a signature
     MUST verify with the key its index names among the keys current at *k*.
     Result: `sealed`, `anchored_at_sn = k`. — else `signature`
   - **sealed period** (only if a period seal was supplied and the
     statement is not anchored): see the periods extension; the signature
     MUST verify with a key current at some point of that period. Result:
     `sealed`, `anchored_at_sn` = the closing event. — else `seal` / `signature`
   - **open**: a signature MUST verify with the issuer's **current** keys
     (those of the last accepted establishment event; none if the
     identifier was abandoned). — else `not-current`
8. **Redemption** (informative result, not a failure): the redemption
   extension.

The statement is **valid** when all steps pass. The recipient is `a.i`
or the conditions `a.req`; who *holds* it is a separate question (section 4,
presentation extension).

### 6.3 What "valid" means: offline and fresh

A signature by the current key is only as current as the KEL the verifier
has. dzq is honest about it:

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
| `schema` | the envelope breaks 3.1/3.5/3.7, a dzq/1.0–1.1 layout is wrong, or the fields break a type the verifier knows |
| `said` | a SAID or the version size does not recompute — content changed |
| `kel` | the issuer's KEL is missing, unreadable or not accepted |
| `no-signature` | no signature |
| `signature` | the signature does not match the keys it must match |
| `not-current` | not sealed, and not signed by the issuer's current keys |
| `seal` | a supplied period seal does not prove the statement |
| `archive` | (`.dzq` only) the archive is refused before verification: section 7 |

and on success `said`, `issuer`, `recipient`, `type` (the type's name, or
none when unknown), `type_known`, `sealed`, `anchored_at_sn`,
`redeemed_at_sn`, when there is a private block `content` = `shown` or
`hidden`, and `re` when shown. Implementations MAY add human-readable
reasons and what extensions report.

## 7. The `.dzq` file

A ZIP archive (deflate or stored) with these entries:

| Entry | Required | Content |
|---|---|---|
| `credential.acdc` | yes | the bundle (section 5), UTF-8; for private content (3.5) the full form, or the compact form in a copy made for showing |
| `metadata.json` | no | for display only, never trusted: `{id, title, message, issuedAt, issuer_aid, recipient_aid}` |
| `assets/` | no | the directory entry, if the ZIP tool writes one |
| `assets/<file name>` | no | a file the statement names (a field of kind `attachment`) |
| `types/`, `types/<SAID>.json` | no | (dzq/1.2) the type document `s` names, so any reader can check the fields (3.6). Ignored unless its SAID recomputes, equals the entry name, and it does not claim the reserved `dzq` source |
| `looks/<SAID>.json`, `looks/<SAID>` | no | (dzq/1.2) the look/1 document the statement names, and the files it uses ([extensions/looks.md](extensions/looks.md)) |
| `signatures.json` | no | **deprecated**; written as `{}` by DzenQ before dzq/1.0. Readers ignore it; writers MUST NOT write it. |

- Writers MUST NOT add other entries. Readers MUST reject
  archives with other entries (`unexpected entry`), so that a future
  version that adds entries is not silently half-read.
- Limits a reader MUST enforce: archive ≤ 25 MB, ≤ 20 entries, each entry
  ≤ 20 MB, ≤ 25 MB uncompressed in total. Names MUST NOT be absolute, use
  `\`, contain `..` path segments or a drive prefix; an asset name MUST NOT
  be empty, start with `.`, contain `/ \ : NUL` or `..`, or exceed 255 bytes.
- A reader MUST verify the statement before it writes anything to disk,
  and MUST extract only assets the statement names (`filename`), only if
  their Blake3-256 equals `d`.
- A carried type document only helps a reader check fields; the statement
  is valid or not without it.
- `metadata.json` MUST NOT be used for any decision. If it disagrees with
  the credential, the credential wins (vector `lying-metadata`).

File extension `.dzq`. Media type `application/vnd.dzq+zip`
(provisional; registration with IANA is planned). DzenQ's earlier
`application/vnd.dzenq.gratitude+zip` SHOULD be read as the same.

## 8. Extensibility and versions

### 8.1 What cannot change within dzq/1.x

The envelope (3.1, 3.5, 3.7), the canonical serialization, the SAID rules
and the fixed SAIDs of 3.4. A statement signed today stays verifiable forever;
a changed type is a new type document with a new SAID, while verifiers keep
accepting statements of the old one.

### 8.2 Unknown things

- Unknown type (a SAID `s` the verifier has no document for): verify the
  envelope; report the type unknown (3.6).
- Fields a known type does not list: reject (`schema`).
- Unknown condition keys: kept, never met (section 4).
- Unknown archive entries: reject (section 7).
- Unknown CESR attachment groups in a KEL: verifiers MAY skip groups whose
  size they know (receipts, first-seen replay couples, seal source couples)
  and MUST otherwise stop.

### 8.3 Categories and condition kinds from other applications

- `category` is free text chosen by the issuer, and **it belongs to the
  issuer**: "help" from Dad and "help" from Mom are two different
  categories that share a name. That is why a statement condition can ask
  for a category only together with `from`.
- New condition keys for `?…` (as `?aid`, `?claim`) are added by a version
  of this document or an extension that defines how they are proved; until
  then every verifier treats them as never met.

### 8.4 Version names

`dzq/MAJOR.MINOR`. Minor versions only add (schemas, condition keys,
extensions, archive entries announced with a version marker). A major
version may change the serialization; it will be a new schema family and
a new file signature.

### 8.5 New types

A new kind of statement — an apology, a notice, an achievement — is a new
type document (3.6), written by whoever needs it, with no change to this
document and no permission: the reference CLI makes one with
`dzq type new`. Everything else stays: the canonical form, SAIDs,
conditions, bundle, `.dzq` file, verification and all extensions work
unchanged, because none of them reads a type's fields.

Before you define a type, ask the question of section 0. A type adds
fields, never rules: if your type needs a rule the envelope does not have
("only once", "only while the balance lasts"), dzq is the wrong tool for
that part.

A type becomes a **base type** (source `dzq`) only when a version of this
document lists its SAID (3.4, 3.8). Applications MUST NOT use a base type
for other meanings; write your own instead.

## 9. Security considerations

- **Double use.** dzq does not prevent it (section 0). A verifier that must
  accept something only once keeps its own record of what it accepted —
  and at that point it is keeping a registry, which is outside dzq.
- **Unknown types.** A valid statement of an unknown type proves who
  signed which bytes, not what the fields mean. Do not act on the fields of
  a type you do not know; a carried type document tells you its rules, not
  that you should trust its author.
- **Stolen keys.** Whoever holds the issuer's current key can issue
  statements in their name until the issuer rotates. Unsealed gratitudes
  signed with the old key become void at the rotation (6.3) — this is
  intended. Gratitudes sealed before the rotation stay valid.
- **Stale KEL.** Offline verification cannot see rotations it was not
  given. See 6.3.
- **Forked KELs.** Two different events at one sequence number are
  duplicity — the one "twice" dzq cannot leave out, because it concerns the
  signer, not the statement (section 0). A verifier keeps the first it saw.
  Statements are only as strong as the verifier's view of the KEL; sources
  that keep "first seen" logs (KERI watchers, witnesses) protect against a
  thief rewriting history after stealing recovery words.
- **Conditions to addresses** (letters extension) are held by whoever
  receives the claim key through that address, including someone who has
  taken over the address. The issuer accepts that risk when choosing an
  address over an AID.
- **Privacy.** A statement is signed, not encrypted. With the private
  content of 3.5, the holder can show it compact: issuer, recipient, date
  and the type's public fields stay visible, the words do not. The full
  form is readable by anyone who has it; a type's public fields and
  1.0.0 / 2.0.0 statements are public in full, forever. Hiding a file in transit is the delivery
  channel's job.
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

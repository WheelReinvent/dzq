# Proposal 0001: private content (show the proof, not the text)

**Status:** draft for discussion · **Target:** dzq/1.1 · **Author:** DzenQ team, 2026-10-19

## Problem

A dzq statement is signed, not encrypted. To prove "I hold three
thank-yous from my neighbours", a holder has to hand over the three files,
and with them every title and message. The verifier (a door, an employer, a
café) learns far more than it needs, and so does anyone it shares them with.

What the verifier usually needs: **who signed it, to whom, when, which
category, and that it is valid.** What it usually does not need: **the
words.**

Statements are signed forever. Whatever is issued without this feature can
never get it later. So it has to exist before statements are issued at
scale.

## Proposal

Split the attribute block into a **public part** and a **private content
block**. The private block can be replaced by its digest when the statement
is shown, and the signature still verifies. This is ACDC's own *partial
disclosure* of nested blocks, with a salt so that short texts cannot be
guessed.

### New layout (gratitude 1.1.0 to an AID, 2.1.0 to a condition)

```json
"a": {
  "d":  "<SAID of a>",
  "i":  "<recipient AID>",            // or "dq": "<condition>"
  "dt": "2026-10-19T12:00:00+00:00",
  "category": "help",
  "c": {                              // private content block
    "d": "<SAID of c>",
    "u": "<salt: 128 random bits, qb64>",
    "title": "Thank you",
    "message": "For fixing my bike.",
    "attachment": { … }               // optional
  }
}
```

The same statement, **compacted** for showing:

```json
"a": {
  "d":  "<same SAID of a>",
  "i":  "<recipient AID>",
  "dt": "2026-10-19T12:00:00+00:00",
  "category": "help",
  "c":  "<SAID of c>"                 // the block replaced by its digest
}
```

### Rules

1. **SAIDs are computed over the compact form.** `c.d` is the SAID of the
   content block (salt included). `a.d` and the top `d` are computed with
   `c` replaced by `c.d`. So the full and the compact form have the same
   `a.d`, the same `d` and the same version size — they are one statement.
2. **The signature covers the compact form.** A verifier given the full
   form first checks `c.d` against the block, replaces the block by `c.d`,
   and then runs the usual checks (SPEC §6) on the compact bytes.
3. **The salt is mandatory and random.** Without it, anyone could test
   guesses ("Thanks!", "Дякую") against `c.d`.
4. **The `.dzq` file keeps the full form.** It is the holder's own copy.
5. **Showing chooses the form per statement.** A presentation
   (`extensions/presentation.md`) may carry each credential compact or
   full. Compact is the default for doors.
6. **Old statements are unchanged.** Schemas 1.0.0 and 2.0.0 stay valid and
   fully public.

### What stays public, and why

| Field | Public | Why |
|---|---|---|
| issuer | yes | the point of a signature is knowing who signed |
| recipient / condition | yes | the verifier must check the holder is the recipient |
| `dt` | yes | ordering, "thanks since 2026", certificates by date |
| `category` | yes, by default | certificates are defined by categories ("3 thank-yous with stamp X") |
| title, message, attachment | **no** | the words are between the two people |

## What changes

- **Spec:** two new gratitude schemas; SPEC §3 gains the content block and
  the compaction rule; §6 gains "expand-check-compact" before step 2.
- **Verifiers:** about 30 lines — recompute `c.d`, compact, then verify as
  today. Unknown-schema behaviour is unchanged for dzq/1.0 verifiers.
- **Issuers (DzenQ):** issue 1.1.0 / 2.1.0 from now on; keep reading 1.0.0
  / 2.0.0.
- **Doors:** receive compact statements; show "a thank-you from X, category
  Y, date Z" without text.
- **Vectors:** full and compact forms of the same statement both valid; a
  compact form with a wrong `c` digest; a full form with an edited message;
  a block without a salt.

## Alignment with ACDC

This is ACDC partial disclosure of a nested block with a SAID and a UUID
salt (`u`), as the ACDC specification describes it. It does not use the
`A` aggregate (selective disclosure of individual fields), which is more
flexible but heavier; the content here is one unit — title and message
make sense together.

## Open questions

1. **Category public or private?** Public makes certificates simple ("show
   me three thank-yous with stamp X" without the text). Private hides more
   but then certificates need a separate proof.
2. **Date public?** Same trade-off; public is simpler.
3. **One private block or several** (title public, message private)? One
   block is simpler and matches how people think about a note.
4. **Encryption for transport** stays out of the format (delivery's job).
   Do we also want an optional "sealed for the recipient" wrapper?
5. **Timing:** ship with the next DzenQ release, before the public pilot.

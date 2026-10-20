# Proposal 0006: open types — dzq keeps the envelope, apps bring the types

**Status:** closed — implemented in dzq/1.2 (SPEC §0, §3.6, §3.7; reference verifier, CLI `dzq type new`, vectors) · **Author:** DzenQ team, 2026-10-20

## Why

Working on promises, apologies and requests showed a pattern: every new
gesture wanted the same envelope (from, to a person or a condition, when,
signature, key history, private block, look) and only differed in a few
fields. Adding each one to the spec makes the spec grow without end and
makes every app wait for us.

The value of the standard is that very different developers — a notice
board, an achievement tracker, thank-yous, apologies, giveaways with
conditions — can come and say: *minimal work, and what I want is protected
by KERI.*

## What

- A **type document**: a JSON Schema with `$id` = its SAID and a `dzq` block
  (`type` = `<source>:<name>`, `version`, `to`, `public`, `private`). The
  statement's `s` is that SAID.
- **Unknown types verify**: envelope, SAIDs and signature; the result says
  `type_known: false`. A reader with the type also checks the fields.
- A `.dzq` may carry its type document as `types/<SAID>.json`.
- The source `dzq` is reserved for a small library of **base types**
  (`types/`): `dzq:gratitude` 1.2.0, `dzq:apology`, `dzq:promise`. Every
  reader knows them; none is special. Use one, or write `myapp:gratitude`
  and carry it in the file.
- Two general private fields: `look` (how to show it) and `re` (the SAID of
  the statement it answers). Both hints.
- **Scope (SPEC §0).** The deciding question: *would anything break if the
  same statement were shown twice?* If yes — balances, tickets, one-time
  coupons, votes — it is not dzq: those need a registry, and dzq does not
  prevent double spending. Not added, ever: registries/TEL, graphs, trust
  chains, free envelope structure, mandatory infrastructure.

## What moved out

- The promise keeps only its fields (`dzq:promise`). `thanks:` conditions,
  "usable" and closing early → experimental (extensions/promises.md,
  `dzq.experimental.promise`), showing how an app layers rules on top.
- The look/1 document stays an optional extension; the pointer is core.

## Compatibility

dzq/1.0 and 1.1 statements are unchanged and valid. Statements made with
the short-lived 1.2 draft schemas (gratitude 1.2.0/2.2.0 and promise
schemas of draft 3) were never issued outside the vectors; their SAIDs are
withdrawn.

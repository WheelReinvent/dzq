# Experimental: promises — earning, using, closing

**Status:** experimental, **not part of dzq**. It shows how an app can build
richer rules on top of dzq without changing it. It may change or go away.
Reference: `dzq.experimental.promise`.

A promise is a statement of the base type `dzq:promise` (SPEC §3.8): every
dzq verifier checks it and, without this extension, simply shows it — a
promise is a statement of intent, nothing more. This
extension answers the question a door asks: **can this holder use it now?**

It is **not double-spend protection** (SPEC §0). Nothing here stops a
holder from showing a promise twice; a door that must give something only
once keeps its own record.

## The `thanks:` condition

```
thanks:<N>/<category>/<issuer>[+<issuer>…][@<since>]
```

*The holder has at least N gratitudes in this category from these issuers
(since this date).*

- `<N>`: 1 to 99999.
- `<category>`: compared with the gratitudes' public `category`, after
  percent-decoding (UTF-8). Encode white space, `%`, `,`, `/`, `+`, `@`,
  `(` and `)`; other characters may appear as they are.
- `<issuer>`: an AID. Several are joined with `+`; their gratitudes add up.
  These are the issuers of the **gratitudes** — the promise always has
  exactly one issuer of its own.
- `@<since>` (optional): RFC 3339; only gratitudes with `a.dt` at or after it
  count. `a.dt` is what each gratitude's issuer stated.

A malformed `thanks:` leaf is never met. A verifier without this
extension treats `thanks:` as an unknown kind, also never met (vector
`thanks-without-extension`).

Examples:

| Promise | Condition |
|---|---|
| lunch for anyone with a "help" thank-you from me | `thanks:1/help/<me>` |
| for Marko or Sofia, after 3 × "cleaned the room" from Dad | `all(any(<Marko>,<Sofia>),thanks:3/cleaned%20the%20room/<Dad>)` |
| to myself, for 100 days without smoking | `all(<me>,thanks:100/no%20smoking/<me>)` |
| 3 thank-yous from either neighbour, since October | `thanks:3/neighbour/<A>+<B>@2026-10-01T00:00:00Z` |

`thanks:` may also appear in a gratitude's condition ("a thank-you to
whoever already has three from me"); the same rules apply.

## Proving it: in a presentation

The holder shows the promise together with the gratitudes that earn
it, in one presentation (extensions/presentation.md). Compact forms are
enough: the door sees who thanked whom, when and in which category, not
the words.

A verifier evaluates the presentation in two passes:

1. **Pool.** Every statement verifies (SPEC §6). The pool is the
   gratitudes (`dzq:gratitude` only — never promises) the holder holds
   directly: `a.i` = holder, or an `a.dq` met through the holder's AID
   alone.
2. **Conditions.** Each credential's condition is evaluated again with
   `thanks:` leaves, counting from the pool (excluding the credential
   itself). A `thanks:` leaf holds when at least N **distinct** gratitudes
   (by SAID) in the pool each
   - have `category` equal to the decoded `<category>`;
   - have an issuer in the leaf's list;
   - have `a.dt` ≥ `<since>`, if given;
   - are **not issued by the holder to themself**, unless the statement
     whose condition is being evaluated is issued by the holder too. A
     thank-you to yourself counts only toward your own promises to
     yourself.

## Usable

A promise in a valid presentation is **usable** when all hold; else
the first failing reason is reported:

| Check | Reason |
|---|---|
| `until` is absent, or later than the verifier's clock | `expired` |
| no close digest (below) in the issuer's KEL | `closed` |
| the holder meets the condition (passes 1 and 2) | `not-earned` |

The presentation is valid only if every promise in it is usable and
every other statement in it is the holder's.

There is no use counter. Showing the same promise twice is between
the holder and the issuer.

## Closing early

```
close digest(S) = SAID of {"d":"<44 #>","t":"close","g":"<promise SAID>"}
```

The issuer anchors it as a digest seal in an `ixn` event. From then on the
promise is not usable by anyone; as a signed record of what was
promised it stays valid, and a verifier reports `closed_at_sn`. Like every
KEL fact, a close is only visible to a verifier with a KEL recent enough;
doors that give real things SHOULD load the issuer's KEL fresh.

## Vectors

Marked `"experimental": "promise"` in `vectors/manifest.json`; a verifier
without the extension skips them. Credential `promise`; presentations `promise-*` (earned, too few,
the same thank-you three times, wrong category, wrong issuer, not a holder,
expired, two issuers adding up, before `since`, self-thanks elsewhere, a
self-promise, a promise is not a thank-you, closed); `close_said
(experimental)` in `vectors/digests.json`.

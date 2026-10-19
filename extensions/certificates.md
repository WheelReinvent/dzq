# Extension: certificates — earning, using, closing (dzq/1.2)

**Status:** part of dzq/1.2. The certificate type itself: SPEC §3.6.

A certificate verifies like any statement (SPEC §6): signed by its issuer,
unchanged. This extension answers the other question a door asks: **can
this holder use it now?**

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
  These are the issuers of the **gratitudes** — the certificate always has
  exactly one issuer of its own.
- `@<since>` (optional): RFC 3339; only gratitudes with `a.dt` at or after it
  count. `a.dt` is what each gratitude's issuer stated.

A malformed `thanks:` leaf is never met. A verifier of an earlier version
treats `thanks:` as an unknown kind, also never met.

Examples:

| Certificate | Condition |
|---|---|
| lunch for anyone with a "help" thank-you from me | `thanks:1/help/<me>` |
| for Marko or Sofia, after 3 × "cleaned the room" from Dad | `all(any(<Marko>,<Sofia>),thanks:3/cleaned%20the%20room/<Dad>)` |
| to myself, for 100 days without smoking | `all(<me>,thanks:100/no%20smoking/<me>)` |
| 3 thank-yous from either neighbour, since October | `thanks:3/neighbour/<A>+<B>@2026-10-01T00:00:00Z` |

`thanks:` may also appear in a gratitude's condition ("a thank-you to
whoever already has three from me"); the same rules apply.

## Proving it: in a presentation

The holder shows the certificate together with the gratitudes that earn
it, in one presentation (extensions/presentation.md). Compact forms are
enough: the door sees who thanked whom, when and in which category, not
the words.

A verifier evaluates the presentation in two passes:

1. **Pool.** Every credential verifies (SPEC §6). The pool is the
   gratitudes (gratitude type only — never certificates) that the holder
   holds **without** counting other gratitudes: `a.i` = holder, or `a.dq`
   met through AID and `claim:` leaves alone.
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

A certificate in a valid presentation is **usable** when all hold; else
the first failing reason is reported:

| Check | Reason |
|---|---|
| `until` is absent, or later than the verifier's clock | `expired` |
| no close digest (below) in the issuer's KEL | `closed` |
| the holder meets the condition (passes 1 and 2) | `not-earned` |

The presentation is valid only if every certificate in it is usable and
every gratitude in it is the holder's.

There is no use counter. Showing the same certificate twice is between
the holder and the issuer.

## Closing early

```
close digest(S) = SAID of {"d":"<44 #>","t":"close","g":"<certificate SAID>"}
```

The issuer anchors it as a digest seal in an `ixn` event. From then on the
certificate is not usable by anyone; as a signed record of what was
promised it stays valid, and a verifier reports `closed_at_sn`. Like every
KEL fact, a close is only visible to a verifier with a KEL recent enough;
doors that give real things SHOULD load the issuer's KEL fresh.

## Vectors

Credentials `certificate*`; presentations `certificate-*` (earned, too few,
the same thank-you three times, wrong category, wrong issuer, not a holder,
expired, two issuers adding up, before `since`, self-thanks elsewhere, a
self-promise, a certificate is not a thank-you, closed); `close_said` in
`vectors/digests.json`.

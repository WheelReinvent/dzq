# Proposal 0002: certificates (a promise, earned or given)

**Status:** implemented in dzq/1.2 (spec, reference verifier, CLI, vectors); DzenQ core pending · **Target:** dzq/1.2 · **Author:** DzenQ team, 2026-10-20

## Problem

A gratitude records the past: *you helped me*. People also want to promise
the future: *a trip to the mountains for Marko and Sofia*, *lunch for anyone
who has a "Help" thank-you from me*, *a dinner for whoever collects five
"Cleaned the room"*. DzenQ does this today with two formats of its own
(`dzenq-key/1`, a public rule by stamps; `dzenq-promise/1`, a private
promise to named people). Neither is part of dzq, so no other app can issue,
hold or check one.

## Proposal

A second **type**, `certificate`, in the same envelope as gratitude.
Everything that is not about the promise itself — issuer, recipient or
condition, date, signature, key history, private content, letters to an
address, presentation — is reused unchanged.

A certificate is **a promise from the issuer to whoever meets its
condition**. The condition is the ordinary `a.dq` (or `a.i` for one
person), plus one new leaf kind that counts gratitudes.

Certificate and gratitude stay separate types on purpose: a gratitude is a
fact that never expires; a certificate expires and can be closed by its
issuer. A certificate never counts as a gratitude in
anyone's condition.

### Fields

Envelope as in SPEC §3.1, then (private-content layout of SPEC §3.5 from the
start; certificate 1.1.0 to one AID, 2.1.0 to a condition):

| Field | Where | Required | Content |
|---|---|---|---|
| `until` | public | no | RFC 3339; after it the certificate cannot be used |
| `what` | private | yes | what is promised, ≤ 200 characters ("a trip to the mountains") |
| `note` | private | no | a few words: why, or what to do to earn it, ≤ 5000 characters |

The issuer of a certificate is always exactly one identifier: the envelope's
`i`. (The gratitudes that earn it may come from many issuers — see
`thanks:` below.)

`until` is public because a door must check it without the text. `what`
stays private, also for certificates that anyone may earn: the promise is
between the issuer and whoever holds it.

### Who can hold it: conditions

Existing leaves already cover named people:

| Certificate | `a.i` / `a.dq` |
|---|---|
| for Marko | `a.i` = Marko's AID |
| for Marko and Sofia | `any(<Marko>,<Sofia>)` |
| for an e-mail address | `claim:<key>` (letters extension) |

New leaf, `thanks:` — *the holder has at least N gratitudes in category C
from these issuers*:

```
thanks:<N>/<category>/<issuer>[+<issuer>…][@<since>]
```

- `<category>` is percent-encoded UTF-8 (so it can hold spaces, `/`, `,`,
  `(`, `)`); compared byte for byte after decoding.
- `<issuer>` is an AID; several are joined with `+` and their gratitudes
  add up ("3 thank-yous from any of my neighbours"). These are the issuers
  of the gratitudes, not of the certificate.
- `@<since>` (optional) is an RFC 3339 date; only gratitudes with `a.dt` at
  or after it count. (`a.dt` is what each gratitude's issuer stated.)

Examples:

| Certificate | Condition |
|---|---|
| lunch for anyone with a "Help" thank-you from me | `thanks:1/help/<me>` |
| for Marko or Sofia, after 5 × "Cleaned the room" from Dad | `all(any(<Marko>,<Sofia>),thanks:5/cleaned%20the%20room/<Dad>)` |
| to myself, for 100 days without smoking | `all(<me>,thanks:100/no%20smoking/<me>)` |
| 3 thank-yous from any of my two neighbours since October | `thanks:3/neighbour/<A>+<B>@2026-10-01T00:00:00Z` |

**Proving a `thanks:` leaf** (in a presentation): the holder includes the
gratitudes. The leaf holds when there are at least N **distinct** gratitudes
(by SAID) that each

1. verify (SPEC §6) — compact (private content hidden) is enough;
2. are held by the presenting holder (`a.i` = holder, or `a.dq` met by the
   holder, presentation extension);
3. are of the gratitude type, with `category` equal to `<category>`;
4. have an issuer in the leaf's issuer list;
5. have `a.dt` ≥ `<since>`, if given;
6. **are not self-issued** (gratitude issuer = holder), unless the
   certificate's issuer is the holder too. A thank-you to yourself counts
   only toward your own promises to yourself.

### No use counter

A certificate has **no "used" state** and no counter. Counting uses needs
one place that counts, which is a centre, and a promise between people does
not need one: if Marko shows the same certificate twice, it is between him
and Dad. The value of a certificate is the history of keeping it — holders
can thank the issuer for a kept promise with an ordinary gratitude, which
is already part of the format. (This follows DzenQ's decision of
2026-10-14: no counters, no used state.)

A certificate is usable while its condition holds, until `until`, and until
the issuer closes it.

### Closing early

The issuer can close a certificate for everyone, for example when it can no
longer keep the promise:

```
close digest(S) = SAID of {"d":"<44 #>","t":"close","g":"<certificate SAID>"}
```

anchored as a digest seal. From the sequence number of that event on, the
certificate cannot be used by anyone.
The certificate itself remains valid as a signed record of what was
promised; it is just no longer usable.

### Verification: valid and usable

A certificate verifies like any statement (SPEC §6). On top of that, a
verifier answers **"can this holder use it now?"**:

| Check | Result if it fails |
|---|---|
| the holder meets the condition (with the gratitudes and claims presented) | `not-earned` |
| `until` is absent or later than the verifier's clock | `expired` |
| no close digest in the issuer's KEL | `closed` |

As with everything KEL-based, `closed` is only as fresh as the issuer's KEL
the verifier has; doors that hand out real things SHOULD load it fresh.

## What changes

- **Spec:** new type `certificate` (schemas 1.1.0 / 2.1.0 of the certificate
  family); new condition leaf `thanks:`; a close record; presentation
  extension gains the "usable" result and the `thanks:` proof rules. No
  per-holder redemption, no counters.
- **Reference verifier and CLI:** `dzq sign --type certificate …`,
  `thanks:` evaluation in presentations, usable / expired / closed.
- **Vectors:** earned / not earned (too few, wrong category, wrong issuer,
  before `since`, self-issued), expired, closed, a certificate presented as
  a gratitude (refused).
- **DzenQ:** `dzenq-key/1` maps to a certificate with a `thanks:` condition;
  `dzenq-promise/1` to a certificate to named people. "All my people" is not
  part of the format: an app that wants it issues certificates to the people
  it means, one by one.

## Decided

- Certificate and gratitude are separate types in the same envelope.
- One certificate issuer; the gratitudes in a `thanks:` condition may come
  from many issuers.
- One free-text field `note` (no separate `ask`).
- No use counter and no "used" state. The issuer can close a certificate
  early.
- `what` is private, always.

## Open questions

None at the moment.

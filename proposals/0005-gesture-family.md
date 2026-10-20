# Idea 0005: the family of gestures — sorry, please, and links between them

**Status:** TBD — an idea to work out, not a proposal yet · **Author:** DzenQ team, 2026-10-20

> **Update, same day.** dzq now has open types (SPEC §3.6) and a general `re` field (SPEC §3.7). So *sorry* and *please* no longer need the spec: any app can define them as type documents today, and `re` covers *in reply to*. Decided: *thank you*, *sorry* and *I promise* are base types (`dzq:gratitude`, `dzq:apology`, `dzq:promise`, SPEC §3.8), none special. *Please* is left to apps for now.

## The family

The words children are taught first — *thank you, sorry, please* — plus
*I promise* fall on two axes:

| | About me | About you |
|---|---|---|
| **Past** | **sorry** — I did you wrong | **thank you** — you did me good |
| **Future** | **I promise** — I will do for you | **please** — do for me |

- *Thank you*, *sorry* and *I promise* are base types; *please* is not (yet).
- *Sorry* (apology) mirrors *thank you* in the past.
- *Please* (request) mirrors *I promise* in the future.

All four are the same envelope (from, to a person or a condition, when,
signature, key history) around a different type.

## Sorry (apology)

Technically almost a twin of gratitude: a signed acknowledgement of a past
fact between two people. The difference is who carries the weight:

- a gratitude is a plus for the recipient, natural to show ("five
  neighbours thanked me"); it counts in `thanks:` conditions;
- an apology is an admission by the **issuer**. For the recipient it proves
  the wrong was acknowledged; showing it to others exposes someone else's
  guilt; for the issuer it is a signed confession that cannot be taken
  back.

So, as first thoughts:

- private by default, shown compact; perhaps **no public category** at all;
- **never counts in someone else's condition.** It may count only in a
  promise from **the same issuer**: "a free lunch for everyone I have
  wronged". The holder shows the issuer's own apology at the issuer's own
  door — nothing new is revealed. A possible leaf: `sorry:<N>`, the issuer
  implied (the promise's issuer). Nobody can fake it: only the issuer signs
  their apologies.
- no apology to yourself.
- an apology often **asks** something — forgiveness, another chance.

## Please (request)

The mirror of a promise: the promise takes an obligation on, the request
asks it of someone else.

- to a person or to a condition ("any neighbour who can help me move");
- private: what is asked, a few words; public: perhaps "relevant until";
- nothing to count: a request gives its holder nothing;
- its signature matters because it proves the request is real ("I really
  asked this") and because others can **answer** it.

DzenQ already has the seed of this: the `ask` of a certificate ("what to do
to earn it") and the «Можу допомогти» reply.

## Links between statements

The gestures form living chains:

- **please → I promise → thank you**: "help me move" → "yes, on Saturday"
  → "thank you for the move";
- **sorry → I forgive you**, or **sorry → I promise to make it right**.

Each link is one statement pointing to another by SAID: *in reply to*,
*for keeping*, *to make right*. ACDC has a standard mechanism for this —
**edges** (the `e` section) — which dzq does not use yet. Links would also
give DzenQ the "history of keeping your word" it wanted: a promise with the
thank-yous that point to it as kept.

This is likely the next big part of the format: how sorry and please fit
depends on it.

## Open questions

1. Forgiveness: a type of its own, or a gratitude in reply ("thank you for
   owning it")?
2. Should an apology have a category at all, or is it unnecessary and
   risky?
3. Which link kinds do we need first (*in reply to*, *for keeping*, *to
   make right*), and do we use ACDC edges as they are?
4. Order of work: links first, or each gesture on its own first?
